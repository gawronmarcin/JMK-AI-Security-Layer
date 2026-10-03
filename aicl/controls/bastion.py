"""C-INJ-BASTION: Tier-2 fast prompt-injection classifier (between deterministic C-INJ-PAT and heavy C-INJ-SEM).

Threats TH-01 (Direct Injection), TH-02 (Indirect Injection).

Architecture Tiering:
1. Deterministic (C-INJ-PAT, priority 20): <0.1 ms regex/Aho-Corasick check. Blocks known signatures immediately.
2. Bastion (C-INJ-BASTION, priority 250): 5-20 ms ML/heuristic classifier.
   - High confidence (score >= threshold_block): Blocks immediately (Action.block), saving Ollama LLM execution.
   - Low confidence (score < threshold_grey): Clean, marks safe (Action.allow, risk=0.0), skipping Ollama LLM execution.
   - Grey zone (threshold_grey <= score < threshold_block): Elevates ctx.risk = score, escalating to Tier 3.
3. Semantic Judge (C-INJ-SEM, priority 500): 300-1500 ms Ollama LLM judge.
   - Runs only when triggered by grey zone risk or untrusted segments.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping
from typing import Any

import httpx

from aicl.models import Action, Decision, Match, Origin, RequestContext, Segment, Severity, Stage
from aicl.registry import register_control

log = logging.getLogger(__name__)

# Core injection heuristics for fast in-process classification
_INJECTION_INDICATORS: tuple[tuple[re.Pattern[str], float, str], ...] = (
    # Direct instruction override & rule bypassing
    (
        re.compile(r"(?i)\b(ignore|disregard|forget|override|bypass)\b[^\n.]{0,60}\b(all\s+)?(rules|instructions|guidelines|prompt|safety|restrictions|constraints)\b"),
        0.95,
        "instruction_override",
    ),
    (
        re.compile(r"(?i)\b(zignoruj|zapomnij|pomiń|odrzuć)\b[^\n.]{0,60}\b(wszystkie\s+)?(zasady|instrukcje|reguły|wytyczne|prompt)\b"),
        0.95,
        "instruction_override_pl",
    ),
    # Persona hijack / Jailbreak framing (DAN, Developer Mode, evil twin)
    (
        re.compile(r"(?i)\b(you are now|act as|pretend to be|roleplay as|simulate)\b[^\n.]{0,50}\b(unrestricted|dan|developer mode|jailbreak|unfiltered|evil|anarchist)\b"),
        0.90,
        "persona_hijack",
    ),
    (
        re.compile(r"(?i)\b(od teraz jesteś|udawaj że|wciel się w|zachowuj się jak)\b[^\n.]{0,50}\b(odblokowany|dan|tryb dewelopera|jailbreak|bezwzględny)\b"),
        0.90,
        "persona_hijack_pl",
    ),
    # System prompt exfiltration / canary discovery
    (
        re.compile(r"(?i)\b(repeat|reveal|print|show|output|leak|echo|dump)\b[^\n.]{0,50}\b(your\s+)?(system prompt|initial instructions|hidden prompt|secret token|developer instructions)\b"),
        0.88,
        "system_prompt_exfiltration",
    ),
    # Delimiter / LLM format token manipulation
    (
        re.compile(r"(?i)(###\s*(instruction|system|human|assistant)|<\|im_start\|>|<\|system\|>|\[INST\]|\[SYSTEM\]|BEGIN\s+SYSTEM\s+PROMPT)"),
        0.85,
        "delimiter_injection",
    ),
    # Code/payload execution framing
    (
        re.compile(r"(?i)\b(execute|eval|run|decode)\b[^\n.]{0,40}\b(payload|base64|hex|shellcode|malicious code)\b"),
        0.82,
        "code_payload_directive",
    ),
    # Social engineering / hypothetical malicious query
    (
        re.compile(r"(?i)\b(in a fictional story|for research only|hypothetically speaking|purely academic)\b[^\n.]{0,60}\b(how to (exploit|hack|bypass|attack|steal|infiltrate))\b"),
        0.75,
        "hypothetical_framing",
    ),
    # Suspicious multi-language or obfuscation markers
    (
        re.compile(r"[\u200B-\u200D\uFEFF]"),
        0.70,
        "zero_width_obfuscation",
    ),
)


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if isinstance(cfg, Mapping):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


def _severity(score: float) -> Severity:
    if score >= 0.95:
        return "critical"
    if score >= 0.85:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"


def classify_text_builtin(text: str) -> tuple[float, str]:
    """Fast in-process classification returning (score, detected_indicator)."""
    max_score = 0.0
    detected = "none"

    for pattern, weight, label in _INJECTION_INDICATORS:
        if pattern.search(text) and weight > max_score:
            max_score = weight
            detected = label

    return round(max_score, 3), detected


async def classify_text_remote(url: str, text: str, timeout: float = 0.5) -> tuple[float, str]:
    """Optional call to an external Bastion classification endpoint."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json={"text": text})
        resp.raise_for_status()
        data = resp.json()
        score = float(data.get("score", data.get("probability", 0.0)))
        label = str(data.get("label", data.get("reason", "remote_bastion")))
        return round(score, 3), label


@register_control
class BastionControl:
    id = "C-INJ-BASTION"
    stages = (Stage.input, Stage.tool_result)
    priority = 250  # Between deterministic C-INJ-PAT (20) and Ollama C-INJ-SEM (500)

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-01", "TH-02"]))
        threshold_block = float(_cfg_val(cfg, "threshold_block", 0.80))
        threshold_grey = float(_cfg_val(cfg, "threshold_grey", 0.30))
        target_action = Action(_cfg_val(cfg, "action", Action.block))

        # Scan all untrusted and candidate segments
        judgeable_origins = {Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact}
        untrusted_segments = [
            s for s in ctx.segments if s.origin in judgeable_origins and s.text.strip()
        ]

        if not untrusted_segments:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                skipped=True,
                reason="no untrusted input segments to evaluate",
            )

        remote_url = os.environ.get("AICL_BASTION_URL") or _cfg_val(cfg, "bastion_url")

        highest_score = 0.0
        best_reason = "clean"
        best_segment: Segment | None = None

        for seg in untrusted_segments:
            texts_to_check = [seg.text] + seg.decoded
            for t in texts_to_check:
                score = 0.0
                reason = "clean"
                if remote_url:
                    try:
                        score, reason = await classify_text_remote(remote_url, t)
                    except (httpx.HTTPError, OSError, ValueError) as err:
                        log.warning("Remote Bastion failed, falling back to local: %s", err)
                        score, reason = classify_text_builtin(t)
                else:
                    score, reason = classify_text_builtin(t)

                if score > highest_score:
                    highest_score = score
                    best_reason = reason
                    best_segment = seg

        # Tiered Decision Logic:
        # 1. High-confidence injection: Block immediately and stop execution
        if highest_score >= threshold_block:
            seg_idx = best_segment.idx if best_segment else 0
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity=_severity(highest_score),
                score=highest_score,
                risk=highest_score,
                reason=f"Bastion classifier detected prompt injection: {best_reason} (score {highest_score:.2f} >= {threshold_block:.2f})",
                matches=[
                    Match(
                        kind=f"bastion_{best_reason}",
                        segment_idx=seg_idx,
                        masked=f"[{best_reason} score={highest_score:.2f}]",
                    )
                ],
            )

        # 2. Grey zone: Allow for now, but elevate ctx.risk so Tier-3 (Ollama C-INJ-SEM) gets triggered
        if highest_score >= threshold_grey:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                severity="medium",
                score=highest_score,
                risk=highest_score,  # Propagates into ctx.risk to gate C-INJ-SEM
                reason=f"Bastion classifier ambiguous (score {highest_score:.2f} in grey zone [{threshold_grey:.2f}, {threshold_block:.2f}] -> escalated to semantic judge)",
            )

        # 3. Clean: Allow and keep risk low, skipping heavy LLM judge
        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            score=highest_score,
            risk=0.0,
            reason=f"Bastion classifier clean (score {highest_score:.2f} < {threshold_grey:.2f})",
        )

"""C-INJ-PAT: Prompt injection pattern matching control (R2, P0). Threats TH-01, TH-02.

Contract notes (ARCHITECTURE.md §4.1, §4.2, §6.8, §7):
- Deterministic pattern matching using feeds.current() signature feed.
- Evaluates input and tool_result stages.
- Scans normalized text and decoded fragments across untrusted segments.
- Graded risk calculation to feed downstream semantic judge gating.
"""

from __future__ import annotations

import re
from typing import Any

from aicl import feeds
from aicl.feeds import Signature
from aicl.models import Action, Decision, Match, Origin, RequestContext, Severity, Stage
from aicl.registry import register_control

_FALLBACK_SIGNATURES: tuple[Signature, ...] = (
    Signature(
        id="SIG-INJ-001",
        set="injection",
        kind="regex",
        pattern=r"(?i)ignore (all )?previous instructions",
        severity="high",
        description="Direct/indirect instruction override (English)",
        refs=["OWASP LLM01:2025", "AML.T0051.000"],
    ),
    Signature(
        id="SIG-INJ-002",
        set="injection",
        kind="regex",
        pattern=r"(?i)zignoruj (wszystkie )?poprzednie instrukcje",
        severity="high",
        description="Direct/indirect instruction override (Polish)",
        refs=["OWASP LLM01:2025", "AML.T0051.000"],
    ),
    Signature(
        id="SIG-INJ-003",
        set="injection",
        kind="regex",
        pattern=r"(?i)disregard (your |all )?previous instructions",
        severity="high",
        description="Instruction override via disregard",
        refs=["OWASP LLM01:2025", "AML.T0051.000"],
    ),
    Signature(
        id="SIG-INJ-004",
        set="injection",
        kind="regex",
        pattern=r"(?i)system override:",
        severity="high",
        description="System override directive",
        refs=["OWASP LLM01:2025", "AML.T0051.001"],
    ),
    Signature(
        id="SIG-INJ-005",
        set="injection",
        kind="regex",
        pattern=r"(?i)nie stosuj się do poprzednich instrukcji",
        severity="high",
        description="Instruction override (Polish alternative)",
        refs=["OWASP LLM01:2025", "AML.T0051.000"],
    ),
)


_SEVERITY_NAMES: dict[int, Severity] = {1: "low", 2: "medium", 3: "high", 4: "critical"}


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class InjectionPatternsControl:
    id: str = "C-INJ-PAT"
    stages: tuple[Stage, ...] = (Stage.input, Stage.tool_result)
    priority: int = 20  # < 100, cheap deterministic check

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        snap = feeds.current()

        # Retrieve configuration from compiled policy or fallback defaults
        sig_sets = _cfg_val(cfg, "signature_sets", ["injection"])
        if isinstance(sig_sets, str):
            sig_sets = [sig_sets]
        min_severity_cfg = str(_cfg_val(cfg, "min_severity", "low"))
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        cfg_threats = list(_cfg_val(cfg, "threat_ids", ["TH-01", "TH-02"]))

        active_signatures: list[Signature] = []
        for s_set in sig_sets:
            active_signatures.extend(snap.for_set(s_set))

        # Standalone fallback if signature feeds were not initialized
        if not active_signatures and "injection" in sig_sets:
            active_signatures = list(_FALLBACK_SIGNATURES)

        matches: list[Match] = []
        matched_origins: set[Origin] = set()
        accumulated_risk = 0.0
        highest_severity_val = 0

        # Risk weights for graded risk calculation (§4.2)
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        risk_weights = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
        min_severity_val = severity_map.get(min_severity_cfg, 1)

        matched_sig_records: list[tuple[Signature, bool, str]] = []

        for segment in ctx.segments:
            # Only scan untrusted input / external sources
            if segment.origin not in (Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact):
                continue

            for sig in active_signatures:
                pattern = snap.regex(sig.id)
                if not pattern and sig.kind == "regex":
                    try:
                        pattern = re.compile(sig.pattern)
                    except re.error:
                        continue
                if not pattern:
                    continue

                sig_sev_val = severity_map.get(sig.severity, 1)
                match_found = False

                # Search normalized view (§5.2)
                if pattern.search(segment.norm):
                    matches.append(Match(
                        kind=sig.id,
                        segment_idx=segment.idx,
                        masked=f"[{sig.id}]",
                        in_decoded=False,
                    ))
                    match_found = True
                    matched_sig_records.append((sig, False, ""))

                # Search decoded views (base64, hex, url, etc.)
                for decoded_text in segment.decoded:
                    if pattern.search(decoded_text):
                        matches.append(Match(
                            kind=sig.id,
                            segment_idx=segment.idx,
                            masked=f"[{sig.id}]",
                            in_decoded=True,
                        ))
                        match_found = True
                        codec = segment.meta.get("decoded_codecs", {}).get(decoded_text, "")
                        matched_sig_records.append((sig, True, codec))

                if match_found:
                    matched_origins.add(segment.origin)
                    accumulated_risk += risk_weights.get(sig.severity, 0.5)
                    highest_severity_val = max(highest_severity_val, sig_sev_val)

        final_risk = min(accumulated_risk, 1.0) if matches else 0.0

        # B1: If decoding budget was exceeded on any segment, escalate risk into grey zone (>= 0.15)
        # without blocking on its own so downstream tiers/telemetry inspect it.
        has_decode_truncated = any(s.meta.get("decode_truncated") for s in ctx.segments)
        if has_decode_truncated:
            final_risk = max(final_risk, 0.20)

        final_action = Action.allow
        severity_str: Severity = "low"

        if matches and highest_severity_val >= min_severity_val:
            final_action = target_action
            severity_str = _SEVERITY_NAMES.get(highest_severity_val, "low")

        # Distinguish direct (TH-01) vs indirect (TH-02) injection by origin
        if "TH-01" in cfg_threats or "TH-02" in cfg_threats:
            detected_threats: list[str] = []
            if any(orig == Origin.user for orig in matched_origins):
                detected_threats.append("TH-01")
            if any(orig in (Origin.tool_result, Origin.retrieved, Origin.artifact) for orig in matched_origins):
                detected_threats.append("TH-02")
            final_threats = [t for t in cfg_threats if t in detected_threats] or cfg_threats
        else:
            final_threats = cfg_threats

        # B3: Build informative reason (up to 3 matched signatures + descriptions + codec)
        if matched_sig_records:
            unique_descs: list[str] = []
            seen_keys: set[tuple[str, bool, str]] = set()
            for sig, in_dec, codec in matched_sig_records:
                key = (sig.id, in_dec, codec)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                item = f'matched {sig.id} "{sig.description}"'
                if in_dec:
                    item += f" (decoded: {codec})" if codec else " (decoded)"
                unique_descs.append(item)
            top3 = unique_descs[:3]
            reason_str = "; ".join(top3)
            if len(unique_descs) > 3:
                reason_str += f"; +{len(unique_descs) - 3} more"
        elif has_decode_truncated:
            reason_str = "decode budget truncated: potential obfuscation detected"
        else:
            reason_str = "no injection patterns detected"

        return Decision(
            control_id=self.id,
            threat_ids=final_threats,
            action=final_action,
            severity=severity_str,
            risk=final_risk,
            reason=reason_str,
            matches=matches,
        )

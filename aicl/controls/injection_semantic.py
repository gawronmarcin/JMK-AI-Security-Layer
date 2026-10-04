"""C-INJ-SEM: semantic prompt-injection judge (R3, P1). Threats TH-01, TH-02.

Contract notes (ARCHITECTURE.md 4.1, 4.2, 7.1):
- Pure w.r.t. the request: returns a Decision, never mutates ctx, never logs.
- Runs late (priority >= 500). Gated by `semantic.run_when`: untrusted segments always, grey-zone
  `ctx.risk`, plus a sampled share. Gating is NOT based on pattern hits alone.
- If every judge call fails, a `JudgeError` is raised on purpose: the engine converts it per `on_error`
  (this control is `fail_open`) and records it in the audit event's `error` field.
- Raw segment text never leaves this module: Match.masked and Decision.reason carry no raw content.
"""
from __future__ import annotations

import asyncio
import difflib
import random
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aicl.controls.pii_secrets import PII_DETECTORS, SECRET_DETECTORS, _scan
from aicl.models import Action, Decision, Match, Origin, RequestContext, Segment, Severity, Stage
from aicl.registry import register_control
from aicl.semantic.ollama import Judge, JudgeError, Verdict
from aicl.semantic.settings import SemanticSettings

JUDGEABLE_ORIGINS = {Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact}


@dataclass
class _State:
    settings: SemanticSettings | None = None
    judge: Judge | None = None
    rng: random.Random = field(default_factory=random.Random)


_STATE = _State()


def configure(settings: SemanticSettings, judge: Judge | None = None, rng: random.Random | None = None) -> None:
    """Called by R1's loader on every policy swap. `judge=None` builds the default Ollama judge."""
    if judge is None and settings.model_ready:
        from aicl.semantic.ollama import OllamaJudge

        judge = OllamaJudge(
            settings.base_url, settings.model,
            timeout_ms=settings.timeout_ms, max_input_chars=settings.max_input_chars,
            max_windows=settings.max_windows,
        )
    _STATE.settings, _STATE.judge = settings, judge
    if rng is not None:
        _STATE.rng = rng


def status() -> dict[str, Any]:
    """For /healthz (public, so no URLs): which judge is configured. Not a liveness probe."""
    s = _STATE.settings
    return {
        "model": s.model if s else None,
        "ready": bool(s is not None and s.model_ready and _STATE.judge is not None),
        "timeout_ms": s.timeout_ms if s else None,
    }


def select_segments(ctx: RequestContext, s: SemanticSettings, rng: random.Random) -> list[Segment]:
    """Pure gating: which segments get judged for this request (latest first, untrusted first, capped)."""
    cands = [x for x in ctx.segments if x.origin in JUDGEABLE_ORIGINS and x.text.strip()]
    chosen: list[Segment] = []
    if s.untrusted_segments:
        chosen += [x for x in reversed(cands) if x.trust == "untrusted"]
    lo, hi = s.risk_between
    in_grey_zone = lo <= ctx.risk <= hi
    sampled = s.sample_rate > 0 and rng.random() < s.sample_rate
    if in_grey_zone or sampled:
        chosen += [x for x in reversed(cands) if x.trust != "untrusted"]
    seen: set[int] = set()
    out: list[Segment] = []
    for x in chosen:
        if x.idx not in seen:
            seen.add(x.idx)
            out.append(x)
    return out[: max(1, s.max_segments)]


_SCRUB = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+|[A-Za-z0-9_\-+/=]{16,}|\d{6,}")


def scrub(text: str, limit: int = 200) -> str:
    """Judge `reason` is model-written and may echo the input: truncate and mask email/long tokens/digits."""
    return _SCRUB.sub("[...]", " ".join(text.split())[:limit])


def _severity(score: float) -> Severity:
    return "critical" if score >= 0.95 else "high" if score >= 0.85 else "medium" if score >= 0.65 else "low"


def _cfg(cfg: Any, key: str, default: Any) -> Any:
    v = cfg.get(key) if isinstance(cfg, Mapping) else getattr(cfg, key, None)
    return default if v is None else v


def mask_secrets_and_pii(text: str) -> str:
    """Mask PII and secrets before passing text to the semantic judge to avoid false positives."""
    all_detectors = [d for group in PII_DETECTORS.values() for d in group] + [
        d for group in SECRET_DETECTORS.values() for d in group
    ]
    spans: list[tuple[int, int, str]] = []
    for det, start, end, _ in _scan(text, all_detectors):
        spans.append((start, end, f"<{det.kind.upper()}>"))
    if not spans:
        return text

    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    merged: list[tuple[int, int, str]] = []
    last_end = 0
    for start, end, placeholder in spans:
        if start < last_end:
            continue
        merged.append((start, end, placeholder))
        last_end = end

    chars = list(text)
    for start, end, placeholder in reversed(merged):
        chars[start:end] = list(placeholder)
    return "".join(chars)


# ctx.risk set by C-INJ-BASTION when it held a block back for this judge (aicl/controls/bastion.py);
# inside the default semantic.run_when.risk_between [0.15, 0.85]
PENDING_BLOCK_RISK = 0.8

_PLACEHOLDER_RE = re.compile(r"[ \t]*<[A-Z0-9_]+>")


def strip_secrets_and_pii(text: str) -> str:
    """PII and secrets cut out (not replaced by a `<AWS_ACCESS_KEY>` label): with the label a small
    judge still reads "exfiltration of credentials" into a user simply sharing one, and the value
    itself says nothing about injection. C-PII-IN / C-SECRET-IN handle the data."""
    return _PLACEHOLDER_RE.sub("", mask_secrets_and_pii(text))


def _new_decoded(text: str, fragment: str) -> bool:
    """A decoded fragment worth showing the judge: mostly words, and not just the text itself
    read another way (a leetspeak/normalized copy turns AKIA...7EXAMPLE into AKIA...tEXAMPLE,
    which no secret detector strips, and looks to a small judge like a hidden payload)."""
    if not fragment.strip():
        return False
    wordish = sum(ch.isalpha() or ch.isspace() for ch in fragment) / len(fragment)
    if wordish < 0.7:
        return False
    return difflib.SequenceMatcher(None, text.casefold(), fragment.casefold()).quick_ratio() < 0.8


def _judge_text(seg: Segment) -> str:
    """Judge the original text, plus decoded fragments that add something, PII and secrets cut out."""
    text = strip_secrets_and_pii(seg.text)
    decoded = [d for d in (strip_secrets_and_pii(f) for f in seg.decoded) if _new_decoded(text, d)]
    if not decoded:
        return text
    return text + "\n[decoded fragments]\n" + "\n".join(decoded)


def _skipped(reason: str) -> Decision:
    return Decision(control_id="C-INJ-SEM", threat_ids=["TH-01", "TH-02"], action=Action.allow,
                    reason=reason, skipped=True)


@register_control
class InjectionSemantic:
    id = "C-INJ-SEM"
    stages = (Stage.input, Stage.tool_result)
    priority = 500

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        st = _STATE
        if st.settings is None or st.judge is None or not st.settings.model_ready:
            return _skipped("semantic judge not configured")
        chosen = select_segments(ctx, st.settings, st.rng)
        if not chosen:
            return _skipped("outside judge run conditions")

        judge = st.judge
        results = await asyncio.gather(
            *(judge.judge(_judge_text(x), untrusted=x.trust == "untrusted") for x in chosen),
            return_exceptions=True,
        )
        verdicts: list[tuple[Segment, Verdict]] = []
        errors: list[JudgeError] = []
        for seg, r in zip(chosen, results):
            if isinstance(r, Verdict):
                verdicts.append((seg, r))
            elif isinstance(r, JudgeError):
                errors.append(r)
            elif isinstance(r, BaseException):
                raise r  # cancellation / programming errors are not judge failures
        if not verdicts:
            if ctx.risk >= PENDING_BLOCK_RISK:
                # the classifier wanted to block and only waited for this judge: it was not
                # cleared, so its verdict stands (on_error fail_open is for the judge's own view)
                return Decision(
                    control_id=self.id, threat_ids=["TH-01", "TH-02"],
                    action=Action(_cfg(cfg, "action", "block")), severity="high",
                    reason=f"semantic judge unavailable ({type(errors[0]).__name__}); "
                           f"the classifier's block (risk {ctx.risk:.2f}) stands",
                    risk=ctx.risk,
                )
            raise errors[0]  # engine applies on_error (fail_open) and records it in the audit `error` field

        seg, best = max(verdicts, key=lambda p: p[1].score)
        threshold = float(_cfg(cfg, "threshold", 0.70))
        action = Action(_cfg(cfg, "action", "block"))
        hit = best.score >= threshold
        return Decision(
            control_id=self.id,
            threat_ids=list(_cfg(cfg, "threat_ids", ["TH-01", "TH-02"])),
            action=action if hit else Action.allow,
            severity=_severity(best.score) if hit else "low",
            score=best.score,
            risk=best.score,
            reason=(f"semantic judge: {scrub(best.reason) or 'injection suspected'} (score {best.score:.2f})"
                    if hit else f"semantic judge below threshold ({best.score:.2f} < {threshold:.2f})"),
            matches=[Match(kind="semantic_injection", segment_idx=seg.idx,
                           masked=f"[{len(seg.text)} chars judged]")] if hit else [],
        )

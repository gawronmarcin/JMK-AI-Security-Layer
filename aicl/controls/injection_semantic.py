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
import random
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from aicl.controls import register_control  # ASSUMPTION: R1 exposes the decorator here (section 4.1)
from aicl.models import Action, Decision, Match, Origin, RequestContext, Segment, Stage
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
        )
    _STATE.settings, _STATE.judge = settings, judge
    if rng is not None:
        _STATE.rng = rng


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


def _severity(score: float) -> str:
    return "critical" if score >= 0.95 else "high" if score >= 0.85 else "medium" if score >= 0.65 else "low"


def _cfg(cfg: Any, key: str, default: Any) -> Any:
    v = cfg.get(key) if isinstance(cfg, Mapping) else getattr(cfg, key, None)
    return default if v is None else v


def _judge_text(seg: Segment) -> str:
    """Judge the original text, plus any decoded (base64/hex/...) fragments so encoded attacks are seen."""
    if not seg.decoded:
        return seg.text
    return seg.text + "\n[decoded fragments]\n" + "\n".join(seg.decoded)


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
            raise errors[0]  # engine applies on_error (fail_open) and records it in the audit `error` field

        seg, best = max(verdicts, key=lambda p: p[1].score)
        threshold = float(_cfg(cfg, "threshold", 0.70))
        action = Action(_cfg(cfg, "action", "block"))
        hit = best.score >= threshold
        return Decision(
            control_id=self.id,
            threat_ids=["TH-01", "TH-02"],
            action=action if hit else Action.allow,
            severity=_severity(best.score) if hit else "low",
            score=best.score,
            risk=best.score,
            reason=(f"semantic judge: {scrub(best.reason) or 'injection suspected'} (score {best.score:.2f})"
                    if hit else f"semantic judge below threshold ({best.score:.2f} < {threshold:.2f})"),
            matches=[Match(kind="semantic_injection", segment_idx=seg.idx,
                           masked=f"[{len(seg.text)} chars judged]")] if hit else [],
        )

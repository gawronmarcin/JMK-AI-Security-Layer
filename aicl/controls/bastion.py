"""C-INJ-BASTION: tier-2 prompt-injection classifier. Threats TH-01 (direct), TH-02 (indirect).

Cascade (priorities): C-INJ-PAT (20, regex + signature feed) -> C-INJ-BASTION (250, small ML
classifier, ~5-20 ms) -> C-INJ-SEM (500, Ollama LLM judge, seconds on CPU).

- risk >= threshold_block: the profile's action (block), first_block stops before the LLM judge.
- threshold_grey <= risk < threshold_block: allow, but `risk` propagates into ctx.risk; the
  semantic judge runs for risk inside `semantic.run_when.risk_between`.
- risk < threshold_grey: clean, reported risk 0 so this control does not trigger the judge.

The classifier backend (none | bastion | remote) comes from `params` and is built by the policy
listener in aicl/integrations.py via `configure()`, once per settings change, not per request.
Without a backend, or while the model is loading, the control reports `skipped`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aicl.models import Action, Decision, Match, Origin, RequestContext, Segment, Severity, Stage
from aicl.registry import register_control
from aicl.semantic.classifier import Classifier, ClassifierError, ClassifierSettings, Score, build, chunks

CONTROL_ID = "C-INJ-BASTION"
THREATS = ["TH-01", "TH-02"]
CLASSIFIED_ORIGINS = {Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact}


@dataclass
class _State:
    settings: ClassifierSettings = field(default_factory=ClassifierSettings)
    classifier: Classifier | None = None


_STATE = _State()


def configure(settings: ClassifierSettings, classifier: Classifier | None = None) -> None:
    """Called on every policy swap whose classifier settings changed. `classifier=None` builds the
    backend from `settings`; tests pass a fake. The old backend is closed in the background."""
    old = _STATE.classifier
    new = classifier if classifier is not None else build(settings)
    _STATE.settings, _STATE.classifier = settings, new
    if new is not None:
        new.start()
    if old is not None and old is not new:
        try:
            asyncio.get_running_loop().create_task(old.aclose())
        except RuntimeError:
            pass


def status() -> dict[str, Any]:
    """For /healthz and scripts/check_semantic.py."""
    c = _STATE.classifier
    return {
        "backend": _STATE.settings.backend,
        "ready": bool(c is not None and c.ready),
        "error": c.error if c is not None else None,
    }


def _cfg(cfg: Any, key: str, default: Any) -> Any:
    v = cfg.get(key) if isinstance(cfg, Mapping) or hasattr(cfg, "get") else None
    return default if v is None else v


def _severity(score: float) -> Severity:
    return "critical" if score >= 0.95 else "high" if score >= 0.85 else "medium" if score >= 0.65 else "low"


def _decision(action: Action, reason: str, **kw: Any) -> Decision:
    return Decision(control_id=CONTROL_ID, threat_ids=kw.pop("threat_ids", THREATS), action=action,
                    reason=reason, **kw)


def texts_for(segments: list[Segment], s: ClassifierSettings) -> list[tuple[Segment, str]]:
    """Original text, its normalized form when normalization removed obfuscation (homoglyphs,
    fullwidth, zero-width), and decoded fragments; chunked to the model's window. Latest
    segments first, capped at `max_texts`."""
    out: list[tuple[Segment, str]] = []
    for seg in reversed(segments):
        variants = [seg.text]
        if seg.norm.casefold() != seg.text.casefold():
            variants.append(seg.norm)
        variants += seg.decoded
        for v in variants:
            out += [(seg, c) for c in chunks(v, s.max_chars, s.max_chunks) if c.strip()]
    return out[: s.max_texts]


@register_control
class BastionControl:
    id = CONTROL_ID
    stages = (Stage.input, Stage.tool_result)
    priority = 250  # after deterministic C-INJ-PAT (20), before the Ollama judge C-INJ-SEM (500)

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg(cfg, "threat_ids", THREATS))
        st = _STATE
        clf = st.classifier
        if clf is None:
            return _decision(Action.allow, "classifier backend not configured (params.backend: none)",
                             skipped=True, threat_ids=threat_ids)
        if not clf.ready:
            clf.start()
            why = clf.error or "classifier model loading"
            return _decision(Action.allow, f"classifier unavailable: {why}", skipped=True, threat_ids=threat_ids)

        segments = [s for s in ctx.segments if s.origin in CLASSIFIED_ORIGINS and s.text.strip()]
        work = texts_for(segments, st.settings)
        if not work:
            return _decision(Action.allow, "no user or untrusted text to classify", skipped=True,
                             threat_ids=threat_ids)

        results = await asyncio.gather(*(clf.classify(t) for _, t in work), return_exceptions=True)
        scored: list[tuple[Segment, Score]] = []
        errors: list[ClassifierError] = []
        for (seg, _), r in zip(work, results):
            if isinstance(r, Score):
                scored.append((seg, r))
            elif isinstance(r, ClassifierError):
                errors.append(r)
            elif isinstance(r, BaseException):
                raise r  # cancellation / programming errors are not classifier failures
        if not scored:
            raise errors[0]  # engine applies on_error (fail_open) and records it in the audit event

        seg, best = max(scored, key=lambda p: p[1].risk)
        threshold_block = float(_cfg(cfg, "threshold_block", 0.80))
        threshold_grey = float(_cfg(cfg, "threshold_grey", 0.30))
        risk = best.risk
        label = best.label or "attack"

        if risk >= threshold_block:
            return _decision(
                Action(_cfg(cfg, "action", "block")),
                f"classifier ({clf.name}): prompt injection, risk {risk:.2f} >= {threshold_block:.2f}",
                threat_ids=threat_ids, severity=_severity(risk), score=risk, risk=risk,
                matches=[Match(kind=f"classifier_{label}", segment_idx=seg.idx,
                               masked=f"[{len(seg.text)} chars classified]")],
            )
        if risk >= threshold_grey:
            return _decision(
                Action.allow,
                f"classifier ({clf.name}): uncertain, risk {risk:.2f} in [{threshold_grey:.2f}, "
                f"{threshold_block:.2f}), escalated to the semantic judge",
                threat_ids=threat_ids, severity="medium", score=risk, risk=risk,
            )
        # risk 0, not the raw score: below threshold_grey this control must not wake the judge
        # through semantic.run_when.risk_between (the raw score stays in `score` for the audit)
        return _decision(
            Action.allow, f"classifier ({clf.name}): clean, risk {risk:.2f} < {threshold_grey:.2f}",
            threat_ids=threat_ids, severity="low", score=risk, risk=0.0,
        )

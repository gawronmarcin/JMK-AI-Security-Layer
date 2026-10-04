"""C-INJ-BASTION: tier-2 prompt-injection classifier. Threats TH-01 (direct), TH-02 (indirect).

Cascade (priorities): C-INJ-PAT (20, regex + signature feed) -> C-INJ-BASTION (250, small ML
classifier, ~5-20 ms) -> C-INJ-SEM (500, Ollama LLM judge, seconds on CPU).

- risk >= threshold_block: the profile's action (block), first_block stops before the LLM judge.
- threshold_grey <= risk < threshold_block: allow, but `risk` propagates into ctx.risk; the
  semantic judge runs for risk inside `semantic.run_when.risk_between`.
- risk < threshold_grey: clean, reported risk 0 so this control does not trigger the judge.

The models are English-only and flag much ordinary non-English text (55% of the corpus's
non-English benign examples with ProtectAI). Hence, per profile:
- `languages` / `other_languages`: text not detected as English is skipped (multilingual
  C-INJ-EMB and C-INJ-SEM cover it), only escalated to the judge, or classified anyway.
- `corroborate`: in the user's own messages a high score blocks only when an earlier tier already
  found the request suspicious (ctx.risk >= corroborate_min_risk, e.g. C-INJ-EMB "uncertain");
  otherwise it is escalated to the judge. Untrusted content (tool output, documents) is blocked
  on the score alone: the model's English false positives were all conversational phrases. Measured on scripts/stack_cases.yaml with all tiers: classifier
  blocking alone -> 11/24 false positives; English-only + corroboration -> 0/24, 46/47 attacks.

The classifier backend (none | bastion | remote) comes from `params` and is built by the policy
listener in aicl/integrations.py via `configure()`, once per settings change, not per request.
Without a backend, or while the model is loading, the control reports `skipped`.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aicl.models import Action, Decision, Match, Origin, RequestContext, Segment, Severity, Stage
from aicl.registry import register_control
from aicl.semantic.classifier import Classifier, ClassifierError, ClassifierSettings, Score, build, texts_for
from aicl.semantic.lang import is_english

CONTROL_ID = "C-INJ-BASTION"
THREATS = ["TH-01", "TH-02"]
CLASSIFIED_ORIGINS = {Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact}
ESCALATE_RISK = 0.5  # inside the default semantic.run_when.risk_between [0.15, 0.85]

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_JSON_SYNTAX_RE = re.compile(r"[{}\[\]]|\"(?:[a-zA-Z0-9_\-]+)\":")
_WS_RE = re.compile(r"\s+")


def clean_for_classifier(text: str) -> str:
    """Strip HTML/XML markup and JSON structural syntax so the model classifies natural text."""
    t = _HTML_TAG_RE.sub(" ", text)
    t = _JSON_SYNTAX_RE.sub(" ", t)
    return _WS_RE.sub(" ", t).strip()


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
    if isinstance(cfg, Mapping) or hasattr(cfg, "get"):
        v = cfg.get(key)
    else:
        v = getattr(cfg, key, None)
    return default if v is None else v


def _severity(score: float) -> Severity:
    return "critical" if score >= 0.95 else "high" if score >= 0.85 else "medium" if score >= 0.65 else "low"


def _decision(action: Action, reason: str, **kw: Any) -> Decision:
    return Decision(control_id=CONTROL_ID, threat_ids=kw.pop("threat_ids", THREATS), action=action,
                    reason=reason, **kw)


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
        s = st.settings
        raw_work = texts_for(segments, s.max_chars, s.max_chunks, s.max_texts)
        if not raw_work:
            return _decision(Action.allow, "no user or untrusted text to classify", skipped=True,
                             threat_ids=threat_ids)

        work: list[tuple[Segment, str]] = []
        for seg, t in raw_work:
            cleaned = clean_for_classifier(t)
            is_untrusted = seg.trust == "untrusted" or seg.origin in (
                Origin.tool_result, Origin.retrieved, Origin.artifact
            )
            # Normal tool outputs often contain trivial json/status with few letters; skip if < 20 letters
            if is_untrusted and sum(c.isalpha() for c in cleaned) < 20:
                continue
            if not cleaned.strip():
                continue
            work.append((seg, cleaned))

        if not work:
            return _decision(
                Action.allow,
                "no text with sufficient content to classify",
                skipped=True,
                threat_ids=threat_ids,
            )

        languages = list(_cfg(cfg, "languages", ["en"]))
        other_languages = str(_cfg(cfg, "other_languages", "skip"))
        if "*" in languages or other_languages == "classify":
            native, foreign = work, []
        else:
            native = [w for w in work if is_english(w[1])]
            foreign = [w for w in work if not is_english(w[1])] if other_languages == "escalate" else []
        if not native and not foreign:
            return _decision(Action.allow, "no English text: left to the multilingual tiers (C-INJ-EMB, C-INJ-SEM)",
                             skipped=True, threat_ids=threat_ids)

        todo = native + foreign
        results = await asyncio.gather(*(clf.classify(t) for _, t in todo), return_exceptions=True)
        scored: list[tuple[Segment, Score, bool]] = []
        errors: list[ClassifierError] = []
        for i, ((seg, _), r) in enumerate(zip(todo, results)):
            if isinstance(r, Score):
                scored.append((seg, r, i < len(native)))
            elif isinstance(r, ClassifierError):
                errors.append(r)
            elif isinstance(r, BaseException):
                raise r  # cancellation / programming errors are not classifier failures
        if not scored:
            raise errors[0]  # engine applies on_error (fail_open) and records it in the audit event

        threshold_block = float(_cfg(cfg, "threshold_block", 0.80))
        threshold_grey = float(_cfg(cfg, "threshold_grey", 0.30))
        corroborate = bool(_cfg(cfg, "corroborate", False))
        corroborate_untrusted = bool(_cfg(cfg, "corroborate_untrusted", False))
        min_risk = float(_cfg(cfg, "corroborate_min_risk", 0.30))
        own = [(seg, sc) for seg, sc, nat in scored if nat]
        other = [(seg, sc) for seg, sc, nat in scored if not nat]
        seg, best = max(own, key=lambda p: p[1].risk) if own else max(other, key=lambda p: p[1].risk)
        risk = best.risk
        label = best.label or "attack"

        def escalate(why: str) -> Decision:
            return _decision(Action.allow, f"classifier ({clf.name}): {why}, escalated to the semantic judge",
                             threat_ids=threat_ids, severity="medium", score=risk, risk=ESCALATE_RISK)

        if own and risk >= threshold_block:
            # corroboration: for user messages (corroborate) and for untrusted tool/retrieved data (corroborate_untrusted).
            # When corroboration is required and no earlier tier raised risk, escalate to judge instead of blocking.
            needs_corroboration = (
                (corroborate and seg.trust != "untrusted")
                or (corroborate_untrusted and seg.trust == "untrusted" and risk < 0.85)
            )
            if needs_corroboration and ctx.risk < min_risk:
                return escalate(f"risk {risk:.2f} but no earlier tier found the text suspicious")
            return _decision(
                Action(_cfg(cfg, "action", "block")),
                f"classifier ({clf.name}): prompt injection, risk {risk:.2f} >= {threshold_block:.2f}",
                threat_ids=threat_ids, severity=_severity(risk), score=risk, risk=risk,
                matches=[Match(kind=f"classifier_{label}", segment_idx=seg.idx,
                               masked=f"[{len(seg.text)} chars classified]")],
            )
        if own and risk >= threshold_grey:
            return escalate(f"uncertain, risk {risk:.2f} in [{threshold_grey:.2f}, {threshold_block:.2f})")
        if not own and risk >= threshold_grey:
            return escalate(f"non-English text, risk {risk:.2f} (English-only model)")
        # risk 0, not the raw score: below threshold_grey this control must not wake the judge
        # through semantic.run_when.risk_between (the raw score stays in `score` for the audit)
        return _decision(
            Action.allow, f"classifier ({clf.name}): clean, risk {risk:.2f} < {threshold_grey:.2f}",
            threat_ids=threat_ids, severity="low", score=risk, risk=0.0,
        )

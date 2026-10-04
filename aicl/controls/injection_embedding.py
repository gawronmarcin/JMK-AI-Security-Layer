"""C-INJ-EMB: multilingual embedding similarity against an attack/benign example corpus.
Threats TH-01 (direct), TH-02 (indirect).

Cascade (priorities): C-INJ-PAT (20, regex + feed) -> C-INJ-EMB (150, embeddings, multilingual)
-> C-INJ-BASTION (250, English classifier) -> C-INJ-SEM (500, LLM judge).

Per text: s_attack / s_benign = mean cosine similarity to the `top_k` closest attack / benign
examples (aicl/semantic/embedding.py). With the profile's thresholds:
- s_attack >= sim_block and margin >= margin_block -> the profile's action (block / flag)
- s_attack >= sim_grey and margin >= margin_grey   -> allow, risk 0.5: escalated to the judge
- otherwise                                        -> clean, risk 0 (does not wake the judge)
where margin = s_attack - s_benign: a text close to a benign hard negative is not an attack.

Similarity values depend on the embedding model: calibrate thresholds with
`scripts/check_semantic.py` after changing `params.model` (docs/SEMANTIC_SETUP.md).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aicl.models import Action, Decision, Match, Origin, RequestContext, Severity, Stage
from aicl.registry import register_control
from aicl.semantic.classifier import texts_for
from aicl.semantic.embedding import EmbeddingIndex, EmbeddingSettings, build_index

CONTROL_ID = "C-INJ-EMB"
THREATS = ["TH-01", "TH-02"]
CLASSIFIED_ORIGINS = {Origin.user, Origin.tool_result, Origin.retrieved, Origin.artifact}
GREY_RISK = 0.5  # inside the default semantic.run_when.risk_between [0.15, 0.85]


@dataclass
class _State:
    settings: EmbeddingSettings = field(default_factory=EmbeddingSettings)
    index: EmbeddingIndex | None = None


_STATE = _State()


def configure(settings: EmbeddingSettings, index: EmbeddingIndex | None = None) -> None:
    """Called on every policy swap whose embedding settings changed (aicl/integrations.py).
    `index=None` builds it from `settings`; tests pass one with a fake embedder."""
    old = _STATE.index
    new = index if index is not None else build_index(settings)
    _STATE.settings, _STATE.index = settings, new
    if new is not None:
        new.start()
    if old is not None and old is not new:
        try:
            asyncio.get_running_loop().create_task(old.aclose())
        except RuntimeError:
            pass


def status() -> dict[str, Any]:
    """For /healthz (public: no URLs)."""
    ix = _STATE.index
    return {
        "backend": _STATE.settings.backend,
        "model": _STATE.settings.model if ix is not None else None,
        "ready": bool(ix is not None and ix.ready),
        "corpus_version": ix.corpus_version if ix is not None else None,
        "examples": ix.size if ix is not None else 0,
        "error": ix.error if ix is not None else None,
    }


def _cfg(cfg: Any, key: str, default: Any) -> Any:
    v = cfg.get(key) if isinstance(cfg, Mapping) or hasattr(cfg, "get") else None
    return default if v is None else v


def _severity(s: float, block: float) -> Severity:
    return "critical" if s >= block + 0.1 else "high" if s >= block else "medium"


def _decision(action: Action, reason: str, threat_ids: list[str], **kw: Any) -> Decision:
    return Decision(control_id=CONTROL_ID, threat_ids=threat_ids, action=action, reason=reason, **kw)


@register_control
class InjectionEmbedding:
    id = CONTROL_ID
    stages = (Stage.input, Stage.tool_result)
    priority = 150  # after deterministic C-INJ-PAT (20), before C-INJ-BASTION (250) and C-INJ-SEM (500)

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg(cfg, "threat_ids", THREATS))
        st = _STATE
        ix = st.index
        if ix is None:
            return _decision(Action.allow, "embedding backend not configured (params.backend: none)",
                             threat_ids, skipped=True)
        ix.maybe_refresh()  # picks up corpus edits (hot reload of the example feed)
        if not ix.ready:
            ix.start()
            return _decision(Action.allow, f"embedding index unavailable: {ix.error or 'building corpus index'}",
                             threat_ids, skipped=True)

        s = st.settings
        segments = [x for x in ctx.segments if x.origin in CLASSIFIED_ORIGINS and x.text.strip()]
        work = texts_for(segments, s.max_chars, s.max_chunks, s.max_texts)
        if not work:
            return _decision(Action.allow, "no user or untrusted text to compare", threat_ids, skipped=True)

        matches = await ix.match([t for _, t in work])  # EmbeddingError -> engine applies on_error
        (seg, _), best = max(zip(work, matches), key=lambda p: (p[1].s_attack, p[1].margin))

        sim_block = float(_cfg(cfg, "sim_block", 0.64))
        sim_grey = float(_cfg(cfg, "sim_grey", 0.59))
        margin_block = float(_cfg(cfg, "margin_block", 0.07))
        margin_grey = float(_cfg(cfg, "margin_grey", 0.03))
        detail = (f"attack sim {best.s_attack:.2f} (closest {best.attack_id}, {best.attack_category}), "
                  f"benign sim {best.s_benign:.2f} (closest {best.benign_id})")

        if best.s_attack >= sim_block and best.margin >= margin_block:
            return _decision(
                Action(_cfg(cfg, "action", "block")), f"embedding match: {detail}", threat_ids,
                severity=_severity(best.s_attack, sim_block), score=best.s_attack,
                risk=min(1.0, max(0.85, best.s_attack)),
                matches=[Match(kind=f"embedding_{best.attack_category or 'attack'}", segment_idx=seg.idx,
                               masked=f"[{len(seg.text)} chars ~ {best.attack_id}]")],
            )
        if best.s_attack >= sim_grey and best.margin >= margin_grey:
            return _decision(Action.allow, f"embedding uncertain, escalated to the semantic judge: {detail}",
                             threat_ids, severity="medium", score=best.s_attack, risk=GREY_RISK)
        return _decision(Action.allow, f"embedding clean: {detail}", threat_ids, severity="low",
                         score=best.s_attack, risk=0.0)

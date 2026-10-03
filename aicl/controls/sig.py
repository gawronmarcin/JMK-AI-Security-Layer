"""C-SIG: Historical attack signature feed matcher (R2, P0/stretch). Threat TH-17.

Contract notes (ARCHITECTURE.md §4.1, §6.8, §7):
- Stages: input, output, tool_call, tool_result
- Priority: 25 (deterministic check)
- Purpose: Cross-cutting matching against externally maintained threat signatures.
"""

from __future__ import annotations

import json
from typing import Any

from aicl import feeds
from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class SignatureFeedControl:
    id: str = "C-SIG"
    stages: tuple[Stage, ...] = (Stage.input, Stage.output, Stage.tool_call, Stage.tool_result)
    priority: int = 25

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-17"]))
        min_severity_cfg = _cfg_val(cfg, "min_severity", "low")
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        min_severity_val = severity_map.get(min_severity_cfg, 1)

        snap = feeds.current()
        matches: list[Match] = []

        # Texts to check
        texts: list[tuple[int | None, str, bool]] = []
        for seg in ctx.segments:
            texts.append((seg.idx, seg.text, False))
            texts.append((seg.idx, seg.norm, False))
            for dec in seg.decoded:
                texts.append((seg.idx, dec, True))

        if ctx.tool_args:
            texts.append((None, json.dumps(ctx.tool_args, default=str), False))

        # Check all regex signatures loaded across all sets
        for sig in snap.signatures:
            if sig.kind == "regex":
                sig_sev_val = severity_map.get(sig.severity, 1)
                if sig_sev_val < min_severity_val:
                    continue
                pat = snap.regex(sig.id)
                if pat is not None:
                    for seg_idx, text, in_dec in texts:
                        if pat.search(text):
                            matches.append(
                                Match(
                                    kind=sig.id,
                                    segment_idx=seg_idx,
                                    masked=f"[{sig.id}]",
                                    in_decoded=in_dec,
                                )
                            )

        if matches:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity="high",
                reason=f"matched historical signature {matches[0].kind}",
                matches=matches,
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            reason="no historical signatures matched",
        )

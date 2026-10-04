"""C-CANARY: System prompt canary leakage detection (R2, P1). Threat TH-18.

Contract notes (ARCHITECTURE.md §4.1, §6.3, §7):
- Stages: output, tool_call
- Priority: 40 (cheap deterministic check)
- Purpose: Prevent system prompt or canary marker leakage to users or tools.
- Scans output segments and tool_call arguments for canary tokens.
"""

from __future__ import annotations

import json
import os
from typing import Any

from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control

_DEFAULT_CANARIES = ("AICL-CANARY-7f3a9c1e", "AICL-CANARY-0b42d8aa")


def canary_tokens(cfg: Any) -> list[str]:
    """Canary tokens from the control config: env vars named in `tokens_env`, literal `tokens`,
    else the built-in defaults. Used by this control (detection) and by the chat flow (injection
    into the system prompt, `inject_into_system_prompt`), so both always agree on the token."""
    tokens: list[str] = []
    tokens_env = _cfg_val(cfg, "tokens_env", ["AICL_CANARY_1", "AICL_CANARY_2"])
    if isinstance(tokens_env, list | tuple):
        for var in tokens_env:
            val = os.environ.get(str(var))
            if val:
                tokens.append(val)
    cfg_tokens = _cfg_val(cfg, "tokens")
    if isinstance(cfg_tokens, list | tuple):
        tokens.extend(str(t) for t in cfg_tokens if t)
    return tokens or list(_DEFAULT_CANARIES)


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class CanaryControl:
    id: str = "C-CANARY"
    stages: tuple[Stage, ...] = (Stage.output, Stage.tool_call)
    priority: int = 40  # < 100, cheap deterministic check

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-18"]))

        tokens = canary_tokens(cfg)

        matches: list[Match] = []

        if ctx.stage == Stage.output:
            for segment in ctx.segments:
                for token in tokens:
                    if token in segment.text or token in segment.norm:
                        matches.append(
                            Match(
                                kind="canary",
                                segment_idx=segment.idx,
                                masked=f"[{token[:11]}...]",
                                in_decoded=False,
                            )
                        )
                    for dec in segment.decoded:
                        if token in dec:
                            matches.append(
                                Match(
                                    kind="canary",
                                    segment_idx=segment.idx,
                                    masked=f"[{token[:11]}...]",
                                    in_decoded=True,
                                )
                            )

        elif ctx.stage == Stage.tool_call and ctx.tool_args:
            args_str = json.dumps(ctx.tool_args, default=str)
            for token in tokens:
                if token in args_str:
                    matches.append(
                        Match(
                            kind="canary",
                            masked=f"[{token[:11]}...]",
                        )
                    )

        if matches:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity="critical",
                reason=f"canary leakage detected ({len(matches)} occurrence(s))",
                matches=matches,
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            reason="no canary tokens detected",
        )

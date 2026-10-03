"""C-TAINT: Taint tracking guard against indirect prompt injection (R3, P2 / Differentiator). Threat TH-19.

Contract notes (ARCHITECTURE.md §1, §5.4, §6.6, §7):
- Stage: tool_call
- Priority: 40
- When untrusted content (web pages, retrieved documents, tool outputs) enters the session,
  the session is marked tainted.
- C-TAINT intercepts proposed tool calls in a tainted session and blocks tools whose privilege
  is in `policy.taint.blocked_privileges_when_tainted` (typically high and critical).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from aicl.models import Action, Decision, RequestContext, Stage
from aicl.registry import register_control
from aicl.state import StateStore, get_store

log = logging.getLogger(__name__)


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if isinstance(cfg, Mapping):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class TaintGuard:
    id = "C-TAINT"
    stages = (Stage.tool_call,)
    priority = 40

    def __init__(self, store: StateStore | None = None) -> None:
        self._store = store

    def _get_store(self) -> StateStore:
        return self._store if self._store is not None else get_store()

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-19"]))

        if not ctx.tool:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="no tool call in context",
            )

        policy = getattr(cfg, "policy", None)
        if policy is None:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="policy not attached",
            )

        taint_spec = policy.raw.taint
        if taint_spec is not None and not taint_spec.enabled:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="taint tracking is disabled in policy",
            )

        # Check if the session or the current context is tainted
        store = self._get_store()
        session = await store.get_session(ctx.session_id)
        is_tainted = ctx.tainted or session.tainted

        if not is_tainted:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="session is not tainted",
            )

        # Session IS tainted: inspect tool privilege
        tool_spec = policy.raw.tools.get(ctx.tool)
        privilege = tool_spec.privilege if tool_spec else "low"

        blocked_privileges = (
            taint_spec.blocked_privileges_when_tainted
            if taint_spec is not None
            else ["high", "critical"]
        )

        if privilege in blocked_privileges:
            cfg_action = _cfg_val(cfg, "action", None)
            if cfg_action in (Action.require_approval, "require_approval"):
                action = Action.require_approval
            elif taint_spec and taint_spec.action:
                action = Action(taint_spec.action)
            elif cfg_action is not None:
                action = Action(cfg_action)
            else:
                action = Action.block
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="critical",
                reason=(
                    f"Execution blocked: session {ctx.session_id!r} is tainted by untrusted data "
                    f"and tool {ctx.tool!r} requires '{privilege}' privilege "
                    f"(blocked privileges: {blocked_privileges})"
                ),
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason=f"tool {ctx.tool!r} has unblocked privilege '{privilege}' in tainted session",
        )

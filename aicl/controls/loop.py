"""C-LOOP: Runaway loop guard on tool calls (R3, P0). Threat TH-13.

Contract notes (ARCHITECTURE.md §5.4, §6.5, §7):
- Stage: tool_call
- Priority: 30 (evaluated after C-TOOL-ACL)
- Detects repeated identical tool calls (same tool + same arguments hash) within `loop_window_seconds`.
- Enforces `max_tool_calls_per_session` cap.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
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
class LoopGuard:
    id = "C-LOOP"
    stages = (Stage.tool_call,)
    priority = 30

    def __init__(self, store: StateStore | None = None, clock=time.time) -> None:
        self._store = store
        self._clock = clock

    def _get_store(self) -> StateStore:
        return self._store if self._store is not None else get_store()

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-13"]))
        action = Action(_cfg_val(cfg, "action", "block"))

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

        budget = policy.budget_for(ctx.role)
        if budget is None:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason=f"role {ctx.role!r} has no budget / loop limits",
            )

        # Hash arguments canonically
        args_payload = json.dumps(ctx.tool_args or {}, sort_keys=True)
        args_hash = hashlib.sha256(args_payload.encode()).hexdigest()[:16]

        store = self._get_store()
        calls = await store.record_tool_call(ctx.session_id, ctx.tool, args_hash)

        # 1. Check max tool calls per session
        if (
            budget.max_tool_calls_per_session is not None
            and len(calls) > budget.max_tool_calls_per_session
        ):
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="high",
                reason=(
                    f"Session tool call cap exceeded for session {ctx.session_id!r}: "
                    f"{len(calls)} > {budget.max_tool_calls_per_session} calls"
                ),
            )

        # 2. Check identical tool calls in sliding window
        if budget.max_identical_tool_calls is not None:
            now = self._clock()
            window_start = now - budget.loop_window_seconds
            matching = [
                c
                for c in calls
                if c.tool == ctx.tool and c.args_hash == args_hash and c.ts >= window_start
            ]
            if len(matching) > budget.max_identical_tool_calls:
                return Decision(
                    control_id=self.id,
                    threat_ids=threat_ids,
                    action=action,
                    severity="high",
                    reason=(
                        f"Runaway loop detected in session {ctx.session_id!r}: tool {ctx.tool!r} "
                        f"called with identical arguments {len(matching)} times within "
                        f"{budget.loop_window_seconds}s (limit: {budget.max_identical_tool_calls})"
                    ),
                )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason="tool call is within loop limits",
        )

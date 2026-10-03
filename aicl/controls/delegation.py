"""C-DELEG: Delegation & privilege escalation control (R3, P2 stretch). Threat TH-09.

Contract notes (ARCHITECTURE.md §4.1, §6.4, §7):
- Stages: ingress, tool_call
- Priority: 22 (runs early before tool execution)
- Purpose: Prevent unbounded agent delegation chains and unauthorized capability widening.
- Limits delegation depth and verifies sub-agent privilege hierarchies.
"""

from __future__ import annotations

from typing import Any

from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control

_DELEGATION_TOOLS = frozenset({
    "delegate_task",
    "call_agent",
    "spawn_agent",
    "run_subagent",
    "delegate",
})

_ROLE_PRIVILEGES = {
    "support_agent": 1,
    "researcher": 2,
    "admin": 3,
}


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class DelegationControl:
    id: str = "C-DELEG"
    stages: tuple[Stage, ...] = (Stage.ingress, Stage.tool_call)
    priority: int = 22

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-09"]))
        max_depth = int(_cfg_val(cfg, "max_delegation_depth", 3))

        # 1. Ingress stage: check delegation depth header if present
        current_depth = 0
        if ctx.segments and ctx.segments[0].meta:
            current_depth = int(ctx.segments[0].meta.get("delegation_depth", 0))

        if current_depth > max_depth:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity="high",
                reason=f"delegation depth {current_depth} exceeds limit {max_depth}",
                matches=[Match(kind="delegation_depth_exceeded", masked=f"[depth:{current_depth}]")],
            )

        # 2. Tool_call stage: inspect delegation tools
        if ctx.stage == Stage.tool_call and ctx.tool in _DELEGATION_TOOLS:
            args = ctx.tool_args or {}
            target_role = str(args.get("role") or args.get("target_role") or "")
            target_depth = int(args.get("depth", current_depth + 1))

            if target_depth > max_depth:
                return Decision(
                    control_id=self.id,
                    threat_ids=threat_ids,
                    action=target_action,
                    severity="high",
                    reason=f"delegation depth {target_depth} exceeds limit {max_depth}",
                    matches=[Match(kind="delegation_depth_exceeded", masked=f"[depth:{target_depth}]")],
                )

            # Check privilege widening
            caller_level = _ROLE_PRIVILEGES.get(ctx.role or "support_agent", 1)
            target_level = _ROLE_PRIVILEGES.get(target_role, caller_level)
            if target_level > caller_level:
                return Decision(
                    control_id=self.id,
                    threat_ids=threat_ids,
                    action=target_action,
                    severity="critical",
                    reason=f"privilege escalation attempt: role '{ctx.role}' delegating to higher role '{target_role}'",
                    matches=[Match(kind="privilege_escalation", masked=f"[{ctx.role}->{target_role}]")],
                )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            reason="delegation limits respected",
        )

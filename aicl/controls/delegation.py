"""C-DELEG: Delegation & privilege escalation control (R3, P2 stretch). Threat TH-09.

Contract notes (ARCHITECTURE.md §4.1, §6.4, §7):
- Stages: ingress, tool_call
- Priority: 22 (runs early before tool execution)
- Purpose: Prevent unbounded agent delegation chains and unauthorized capability widening.

Who may delegate to whom comes from the policy: delegating to a role that has nothing the caller
lacks (tools, models, memory namespaces) is always fine; any widening must be listed in
`roles.<caller>.may_delegate_to` ("*" = any role).

Depth is tracked by the gateway, not taken from the client: a session's depth is 0 unless the
session joined a delegation through a ticket (aicl/flows: `X-AICL-Delegation-Ticket`, issued
when a delegation tool call goes through). A delegated task gets max(session depth + 1, the
`depth` argument): a client can claim a deeper chain, never a shallower one. The limit is the
smaller of the control's `max_delegation_depth` and the role budget's `max_delegation_depth`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control
from aicl.state import StateStore, get_store

DELEGATION_TOOLS = frozenset({
    "delegate_task",
    "call_agent",
    "spawn_agent",
    "run_subagent",
    "delegate",
})
_DELEGATION_TOOLS = DELEGATION_TOOLS


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def delegated_depth(session_depth: int, args: Mapping[str, Any] | None) -> int:
    """Depth of the task a delegation call creates (see the module docstring)."""
    claimed = _as_int((args or {}).get("depth"))
    return max(session_depth + 1, claimed or 0)


def target_role_of(args: Mapping[str, Any] | None) -> str:
    args = args or {}
    return str(args.get("role") or args.get("target_role") or "")


def _covers(caller: list[str], target: list[str]) -> bool:
    """Caller's grant covers the target's ("*" covers anything, only "*" covers "*")."""
    return "*" in caller or ("*" not in target and set(target) <= set(caller))


def _widening(policy: Any, caller_role: str, target_role: str) -> list[str]:
    """Kinds of permission the target role has and the caller role lacks."""
    caller, target = policy.role(caller_role), policy.role(target_role)
    if caller is None or target is None:
        return ["unknown role"]
    return [kind for kind in ("tools", "models", "memory_namespaces")
            if not _covers(getattr(caller, kind), getattr(target, kind))]


@register_control
class DelegationControl:
    id: str = "C-DELEG"
    stages: tuple[Stage, ...] = (Stage.ingress, Stage.tool_call)
    priority: int = 22

    def __init__(self, store: StateStore | None = None) -> None:
        self._store = store

    def _get_store(self) -> StateStore:
        return self._store if self._store is not None else get_store()

    def _limit(self, cfg: Any, role: str | None) -> int:
        limit = int(_cfg_val(cfg, "max_delegation_depth", 3))
        policy = getattr(cfg, "policy", None)
        budget = policy.budget_for(role) if policy is not None else None
        if budget is not None and budget.max_delegation_depth is not None:
            limit = min(limit, budget.max_delegation_depth)
        return limit

    def _block(self, cfg: Any, reason: str, kind: str, masked: str, severity: str = "high") -> Decision:
        return Decision(
            control_id=self.id,
            threat_ids=list(_cfg_val(cfg, "threat_ids", ["TH-09"])),
            action=Action(_cfg_val(cfg, "action", Action.block)),
            severity=severity,  # type: ignore[arg-type]
            reason=reason,
            matches=[Match(kind=kind, masked=masked)],
        )

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-09"]))
        limit = self._limit(cfg, ctx.role)
        session_depth = (await self._get_store().get_session(ctx.session_id)).delegation_depth

        # 1. Every request: a delegated session deeper than the limit (e.g. after the limit was lowered)
        if session_depth > limit:
            return self._block(cfg, f"session delegation depth {session_depth} exceeds limit {limit}",
                               "delegation_depth_exceeded", f"[depth:{session_depth}]")

        # 2. Tool_call stage: a new delegation
        if ctx.stage == Stage.tool_call and ctx.tool in DELEGATION_TOOLS:
            args = ctx.tool_args if isinstance(ctx.tool_args, Mapping) else {}
            depth = delegated_depth(session_depth, args)
            if depth > limit:
                return self._block(cfg, f"delegation depth {depth} exceeds limit {limit}",
                                   "delegation_depth_exceeded", f"[depth:{depth}]")

            caller_role = ctx.role or ""
            target_role = target_role_of(args) or caller_role
            policy = getattr(cfg, "policy", None)
            if policy is None:
                return self._block(cfg, "policy not attached: delegation cannot be verified",
                                   "privilege_escalation", f"[{caller_role}->{target_role}]")
            role_spec = policy.role(caller_role)
            allowed = role_spec.may_delegate_to if role_spec is not None else []
            if target_role != caller_role and "*" not in allowed and target_role not in allowed:
                widening = _widening(policy, caller_role, target_role)
                if widening:
                    return self._block(
                        cfg,
                        f"privilege escalation attempt: role '{caller_role}' delegating to role "
                        f"'{target_role}' ({', '.join(widening)}), not in roles.{caller_role}.may_delegate_to "
                        f"{allowed}",
                        "privilege_escalation", f"[{caller_role}->{target_role}]", severity="critical",
                    )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            reason="delegation limits respected",
        )

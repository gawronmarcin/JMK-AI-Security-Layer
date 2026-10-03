"""C-MEM-ACL: Memory / RAG namespace access control (R3, P1). Threat TH-10.

Contract notes (ARCHITECTURE.md §4.1, §6.6, §7):
- Stages: tool_call, input
- Priority: 25 (after C-TOOL-ACL, before C-LOOP / C-TAINT; deterministic)
- Purpose: Prevent agents from reading or writing restricted memory namespaces
  (e.g. kb_hr) that are not granted to their role.

Namespace detection:
  * tool_call stage: inspects ctx.tool_args for a "namespace" or "memory_namespace"
    key. Known memory-tool names are also checked so the control catches arg-less
    calls to restricted-namespace tools.
  * input stage: inspects segments with Origin.retrieved (RAG-retrieved documents)
    — their meta["namespace"] is checked if present.

Policy config (example):
    memory:
      namespaces:
        kb_public:   {sensitivity: public}
        kb_research: {sensitivity: internal}
        kb_hr:       {sensitivity: restricted}   # no role carries it → always blocked

    roles:
      support_agent:
        memory_namespaces: [kb_public]
      researcher:
        memory_namespaces: [kb_public, kb_research]
      admin:
        memory_namespaces: ["*"]   # wildcard
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from aicl.models import Action, Decision, Match, Origin, RequestContext, Stage
from aicl.registry import register_control

log = logging.getLogger(__name__)

# Tool names that are expected to carry a namespace argument.
# This list is guidance; the actual check is on the argument value.
_MEMORY_TOOL_NAMES = frozenset({
    "memory_read", "memory_write", "memory_search", "memory_delete",
    "rag_query", "rag_store", "kb_search", "kb_read",
})

# Argument keys that identify a memory namespace.
_NS_KEYS = ("namespace", "memory_namespace", "ns")


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if isinstance(cfg, Mapping):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


def _role_allows_namespace(policy: Any, role: str | None, namespace: str) -> bool:
    """Return True if the role is allowed to access the namespace."""
    r = policy.role(role)
    if r is None:
        return False
    allowed: list[str] = r.memory_namespaces
    return "*" in allowed or namespace in allowed


def _namespace_exists(policy: Any, namespace: str) -> bool:
    """Return True if the namespace is declared in the policy memory block."""
    mem = policy.raw.memory
    if mem is None:
        return True  # no memory section → no restrictions configured
    return namespace in mem.namespaces


def _extract_namespace_from_args(tool_args: dict[str, Any] | None) -> str | None:
    """Pull the namespace value out of tool arguments, or return None."""
    if not tool_args:
        return None
    for key in _NS_KEYS:
        val = tool_args.get(key)
        if isinstance(val, str) and val:
            return val
    return None


@register_control
class MemoryAcl:
    id = "C-MEM-ACL"
    stages = (Stage.tool_call, Stage.input)
    priority = 25

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-10"]))
        action = Action(_cfg_val(cfg, "action", "block"))

        policy = getattr(cfg, "policy", None)
        if policy is None:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="policy not attached",
            )

        # If no memory section is configured, there is nothing to restrict.
        if policy.raw.memory is None:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="no memory namespaces configured in policy",
            )

        # --- tool_call stage: check the tool's namespace argument ----------------
        if ctx.stage == Stage.tool_call:
            return self._check_tool_call(ctx, cfg, action, threat_ids, policy)

        # --- input stage: check retrieved segments' namespace metadata -----------
        if ctx.stage == Stage.input:
            return self._check_retrieved_segments(ctx, cfg, action, threat_ids, policy)

        # Should never be reached (stages tuple guards this).
        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason="stage not applicable",
        )

    # ---------------------------------------------------------------------- helpers

    def _check_tool_call(
        self,
        ctx: RequestContext,
        cfg: Any,
        action: Action,
        threat_ids: list[str],
        policy: Any,
    ) -> Decision:
        tool = ctx.tool
        args = ctx.tool_args or {}

        # Only check tools that operate on memory namespaces.
        is_memory_tool = tool in _MEMORY_TOOL_NAMES if tool else False
        namespace = _extract_namespace_from_args(args)

        if not is_memory_tool and namespace is None:
            # Not a memory tool and no namespace arg → not our concern.
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="tool call does not involve a memory namespace",
            )

        if namespace is None:
            # Memory tool but no explicit namespace arg; treat as implicitly allowed.
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason=f"memory tool {tool!r} called without explicit namespace argument",
            )

        return self._check_namespace(
            ctx, action, threat_ids, policy, namespace,
            context=f"tool {tool!r} argument namespace={namespace!r}",
        )

    def _check_retrieved_segments(
        self,
        ctx: RequestContext,
        cfg: Any,
        action: Action,
        threat_ids: list[str],
        policy: Any,
    ) -> Decision:
        violations: list[str] = []
        matches: list[Match] = []

        for seg in ctx.segments:
            if seg.origin != Origin.retrieved:
                continue
            namespace = seg.meta.get("namespace")
            if not isinstance(namespace, str) or not namespace:
                continue

            if not _role_allows_namespace(policy, ctx.role, namespace):
                violations.append(namespace)
                matches.append(
                    Match(
                        kind="unauthorized_namespace",
                        segment_idx=seg.idx,
                        masked=f"namespace={namespace!r}",
                    )
                )

        if violations:
            unique = sorted(set(violations))
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="high",
                reason=(
                    f"Retrieved segment(s) from restricted namespace(s) "
                    f"{unique} — role {ctx.role!r} is not authorised"
                ),
                matches=matches,
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason="all retrieved segments are from authorised namespaces",
        )

    def _check_namespace(
        self,
        ctx: RequestContext,
        action: Action,
        threat_ids: list[str],
        policy: Any,
        namespace: str,
        context: str,
    ) -> Decision:
        if not _namespace_exists(policy, namespace):
            # Unknown namespace: block — don't let agents probe for undeclared stores.
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="medium",
                reason=f"Unknown namespace {namespace!r} in {context}; only declared namespaces are accessible",
            )

        if not _role_allows_namespace(policy, ctx.role, namespace):
            sensitivity = "unknown"
            if policy.raw.memory and namespace in policy.raw.memory.namespaces:
                sensitivity = policy.raw.memory.namespaces[namespace].sensitivity
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="high",
                reason=(
                    f"Role {ctx.role!r} is not authorised to access namespace "
                    f"{namespace!r} (sensitivity: {sensitivity}) via {context}"
                ),
                matches=[Match(kind="unauthorized_namespace", masked=f"namespace={namespace!r}")],
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason=f"Role {ctx.role!r} is authorised to access namespace {namespace!r}",
        )

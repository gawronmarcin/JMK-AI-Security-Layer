"""C-TOOL-ACL: Tool authorization and argument schema validation (R3, P0). Threat TH-07.

Contract notes (ARCHITECTURE.md §4.1, §6.3, §6.6, §7):
- Stage: tool_call
- Priority: 20 (deterministic)
- Role ACL: checks if the calling role is permitted to invoke the tool (supports wildcard "*").
- Argument validation: when `cfg.validate_args` is true, validates `ctx.tool_args` against
  the tool's `arg_schema` defined in the policy.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from aicl.models import Action, Decision, RequestContext, Stage
from aicl.registry import register_control

log = logging.getLogger(__name__)

try:
    import jsonschema

    def _validate_schema(data: Any, schema: dict[str, Any]) -> str | None:
        try:
            jsonschema.validate(instance=data, schema=schema)
            return None
        except jsonschema.ValidationError as exc:
            return exc.message
        except Exception as exc:  # noqa: BLE001
            return f"invalid schema: {exc}"

except ImportError:  # pragma: no cover
    # Fallback basic validator if jsonschema is somehow unavailable
    def _validate_schema(data: Any, schema: dict[str, Any]) -> str | None:
        req = schema.get("required") or []
        if isinstance(data, dict):
            for k in req:
                if k not in data:
                    return f"'{k}' is a required property"
        return None


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if isinstance(cfg, Mapping):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class ToolAcl:
    id = "C-TOOL-ACL"
    stages = (Stage.tool_call,)
    priority = 20

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-07"]))
        action = Action(_cfg_val(cfg, "action", "block"))
        validate_args = bool(_cfg_val(cfg, "validate_args", True))

        if not ctx.tool:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=Action.allow,
                reason="no tool specified in context",
            )

        try:
            policy = cfg.policy
        except AttributeError:
            policy = None
        if policy is None:
            # Without the policy the role's tools are unknown: fail closed (authorization control).
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="high",
                reason="policy not attached, tool permissions unknown",
            )

        # 1. Role ACL check
        if not policy.role_allows_tool(ctx.role, ctx.tool):
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="high",
                reason=f"tool {ctx.tool!r} is not permitted for role {ctx.role!r}",
            )

        # 2. Argument schema validation
        if validate_args:
            tool_spec = policy.raw.tools.get(ctx.tool)
            if tool_spec and tool_spec.arg_schema:
                args = ctx.tool_args if ctx.tool_args is not None else {}
                err = _validate_schema(args, tool_spec.arg_schema)
                if err is not None:
                    return Decision(
                        control_id=self.id,
                        threat_ids=threat_ids,
                        action=action,
                        severity="medium",
                        reason=f"tool {ctx.tool!r} arguments failed schema validation: {err}",
                    )

        # 3. Guard against SSRF / cloud metadata targets and dangerous schemes
        args = ctx.tool_args or {}
        if isinstance(args, dict):
            for k, val in args.items():
                if isinstance(val, str) and ("url" in k.lower() or "uri" in k.lower()):
                    low_val = val.lower().strip()
                    if any(bad in low_val for bad in ("169.254.169.254", "metadata.google.internal", "metadata.azure.com")) or low_val.startswith(("file://", "gopher://", "dict://")):
                        return Decision(
                            control_id=self.id,
                            threat_ids=threat_ids,
                            action=action,
                            severity="critical",
                            reason=f"tool {ctx.tool!r} argument {k!r} contains prohibited SSRF/metadata target",
                        )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            reason=f"tool {ctx.tool!r} authorized",
        )

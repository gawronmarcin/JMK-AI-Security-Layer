"""R1 Ingress Controls: C-MODEL-ALLOW and C-SIZE (§6.3, §7).

Threats:
  - TH-06: Disallowed model selection (C-MODEL-ALLOW)
  - TH-20: Oversized input / DoS via oversized payload, excessive messages or huge messages (C-SIZE)

Contract notes (ARCHITECTURE.md v0.2):
  - Controls are pure: return a Decision, never mutate ctx, never log.
  - Stage: ingress
  - C-MODEL-ALLOW checks if the model requested in ctx is permitted for ctx.role according to policy roles.
  - C-SIZE validates input segments and artifacts against size limit parameters (max_body_bytes, max_messages, max_chars_per_message, max_artifact_bytes).
"""

from __future__ import annotations

from typing import Any

from aicl.models import Action, Decision, Match, RequestContext, Severity, Stage
from aicl.registry import register_control


def _cfg(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    if hasattr(cfg, key):
        return getattr(cfg, key)
    return default


@register_control
class ModelAllowlist:
    """C-MODEL-ALLOW: enforces that the identity's role is allowed to access the requested model."""

    id = "C-MODEL-ALLOW"
    threat_ids = ("TH-06",)
    stages = (Stage.ingress,)
    priority = 10  # ingress check runs before heavier controls

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg(cfg, "threat_ids", self.threat_ids))
        action = Action(_cfg(cfg, "action", Action.block))

        # If no model requested (e.g. artifact scan or non-model flow), allow
        if not ctx.model:
            return Decision(control_id=self.id, threat_ids=threat_ids, action=Action.allow)

        # Access policy through cfg.policy if attached
        policy = getattr(cfg, "policy", None)
        if policy is not None:
            # Check if role permits this model
            allowed = policy.role_allows_model(ctx.role, ctx.model)
        else:
            # Fallback when policy is not attached to cfg (e.g. standalone test)
            allowed = True

        if not allowed:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="high",
                reason=f"model {ctx.model!r} is not allowed for role {ctx.role!r}",
                matches=[Match(kind="disallowed_model", masked=ctx.model)],
            )

        return Decision(control_id=self.id, threat_ids=threat_ids, action=Action.allow)


@register_control
class SizeLimits:
    """C-SIZE: protects against DoS / excessive payload sizes."""

    id = "C-SIZE"
    threat_ids = ("TH-20",)
    stages = (Stage.ingress,)
    priority = 20

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        threat_ids = list(_cfg(cfg, "threat_ids", self.threat_ids))
        action = Action(_cfg(cfg, "action", Action.block))

        max_messages = _cfg(cfg, "max_messages")
        max_chars_per_message = _cfg(cfg, "max_chars_per_message")
        max_body_bytes = _cfg(cfg, "max_body_bytes")
        max_artifact_bytes = _cfg(cfg, "max_artifact_bytes")

        # 1. Check message count limit
        if max_messages is not None and len(ctx.segments) > int(max_messages):
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=action,
                severity="medium",
                reason=f"message count {len(ctx.segments)} exceeds limit of {max_messages}",
                matches=[Match(kind="message_count_limit", masked=f"{len(ctx.segments)} messages")],
            )

        # 2. Check per-message character limit
        if max_chars_per_message is not None:
            limit = int(max_chars_per_message)
            for seg in ctx.segments:
                if len(seg.text) > limit:
                    return Decision(
                        control_id=self.id,
                        threat_ids=threat_ids,
                        action=action,
                        severity="medium",
                        reason=f"message[{seg.idx}] length {len(seg.text)} chars exceeds limit of {limit}",
                        matches=[
                            Match(
                                kind="message_length_limit",
                                segment_idx=seg.idx,
                                masked=f"{len(seg.text)} chars",
                            )
                        ],
                    )

        # 3. Check total body bytes (sum of text UTF-8 bytes in segments or raw_body_bytes in segment meta)
        if max_body_bytes is not None:
            limit = int(max_body_bytes)
            # Check if any segment has raw_body_bytes metadata or sum text bytes
            body_bytes = None
            for seg in ctx.segments:
                if "raw_body_bytes" in seg.meta:
                    body_bytes = seg.meta["raw_body_bytes"]
                    break
            if body_bytes is None:
                body_bytes = sum(len(seg.text.encode("utf-8")) for seg in ctx.segments)

            if body_bytes > limit:
                return Decision(
                    control_id=self.id,
                    threat_ids=threat_ids,
                    action=action,
                    severity="medium",
                    reason=f"request body size {body_bytes} bytes exceeds limit of {limit}",
                    matches=[Match(kind="body_size_limit", masked=f"{body_bytes} bytes")],
                )

        # 4. Check artifact byte limit if artifact is present
        if ctx.artifact is not None and max_artifact_bytes is not None:
            limit = int(max_artifact_bytes)
            artifact_size = len(ctx.artifact)
            if artifact_size > limit:
                return Decision(
                    control_id=self.id,
                    threat_ids=threat_ids,
                    action=action,
                    severity="medium",
                    reason=f"artifact size {artifact_size} bytes exceeds limit of {limit}",
                    matches=[Match(kind="artifact_size_limit", masked=f"{artifact_size} bytes")],
                )

        return Decision(control_id=self.id, threat_ids=threat_ids, action=Action.allow)

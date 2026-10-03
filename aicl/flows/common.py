"""Pieces shared by all flows: authentication (C-AUTH), the audit record, responses."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from aicl.audit import new_event
from aicl.engine import StageResult
from aicl.errors import GatewayError
from aicl.models import (
    ACTION_PRECEDENCE,
    Action,
    AuditDecision,
    Decision,
    Endpoint,
    ErrorType,
    Latency,
    Match,
    Origin,
    Profile,
    Segment,
    Trust,
    Usage,
    strongest_action,
)
from aicl.normalize import build_segment
from aicl.policy.schema import CompiledPolicy, IdentitySpec
from aicl.runtime import Runtime
from aicl.utils import new_id

AUTH_CONTROL_ID = "C-AUTH"
AUTH_THREATS = ["TH-08"]
SIZE_CONTROL_ID = "C-SIZE"
# Blocks by these controls are answered as 429 aicl_budget_exceeded (§5.3).
_BUDGET_CONTROLS = frozenset({"C-BUDGET"})


class BodyTooLarge(Exception):
    """Raised by a BodyReader as soon as the body is known to exceed the limit."""

    def __init__(self, size: int):
        super().__init__(f"body exceeds limit ({size} bytes read or declared)")
        self.size = size


# Reads the request body; with a limit it stops early and raises BodyTooLarge.
BodyReader = Callable[[int | None], Awaitable[bytes]]

# Errors that are security outcomes carry a final action; the rest (bad request,
# upstream failure) are recorded in the audit `error` field instead.
_ERROR_ACTION: dict[ErrorType, Action] = {
    ErrorType.auth_failed: Action.block,
    ErrorType.blocked: Action.block,
    ErrorType.budget_exceeded: Action.block,
    ErrorType.approval_required: Action.require_approval,
}


@dataclass
class FlowResponse:
    status: int
    body: dict[str, Any]
    headers: dict[str, str]
    stream: bool = False  # re-emit body as SSE (pseudo-streaming)


def authenticate(
    policy: CompiledPolicy,
    headers: Mapping[str, str],
    env: Mapping[str, str] | None = None,
) -> IdentitySpec:
    """C-AUTH: Bearer key -> identity; a claimed X-AICL-Agent must match that identity."""
    auth = headers.get("authorization", "")
    scheme, _, key = auth.partition(" ")
    identity = policy.identity_for_key(key.strip()) if scheme.lower() == "bearer" and key.strip() else None
    claimed = headers.get("x-aicl-agent")

    if identity is None and env and env.get("AICL_ADMIN_OPEN") == "1":
        if claimed and claimed in policy.identities:
            return policy.identities[claimed]
        if "admin" in policy.identities:
            return policy.identities["admin"]
        if policy.identities:
            return next(iter(policy.identities.values()))

    if identity is None:
        raise GatewayError(
            ErrorType.auth_failed, "missing or invalid API key", _auth_decision("unknown API key")
        )
    if claimed is not None and claimed != identity.id:
        if identity.role == "admin" and claimed in policy.identities:
            return policy.identities[claimed]
        raise GatewayError(
            ErrorType.auth_failed,
            "X-AICL-Agent does not match the API key's identity",
            _auth_decision("agent id mismatch (impersonation attempt)"),
        )
    return identity


def auth_decision(reason: str) -> Decision:
    return Decision(
        control_id=AUTH_CONTROL_ID,
        threat_ids=AUTH_THREATS,
        action=Action.block,
        severity="high",
        reason=reason,
    )


_auth_decision = auth_decision


@dataclass
class RequestRecord:
    """Collects everything about one request; turns into the audit event and response headers."""

    rt: Runtime
    endpoint: Endpoint
    headers: Mapping[str, str]
    policy: CompiledPolicy = field(init=False)
    feed_version: str | None = field(init=False)
    request_id: str = field(default_factory=lambda: new_id("req"))
    session_id: str = field(init=False)
    identity: IdentitySpec | None = None
    profile: Profile | None = None
    model: str | None = None
    stages: list[StageResult] = field(default_factory=list)
    extra_decisions: list[Decision] = field(default_factory=list)
    upstream_called: bool = False
    upstream_ms: float = 0.0
    usage: Usage | None = None
    errors: list[str] = field(default_factory=list)
    _t0: float = field(default_factory=time.perf_counter)

    def __post_init__(self) -> None:
        # One snapshot of policy and feed per request, even if they are reloaded meanwhile.
        self.policy = self.rt.policy
        self.feed_version = self.rt.feeds.current().version
        self.session_id = self.headers.get("x-aicl-session") or new_id("sess")

    def authenticate(self) -> IdentitySpec:
        self.identity = authenticate(self.policy, self.headers, getattr(self.rt, "env", None))
        self.profile = self.policy.profile_for(self.identity)
        return self.identity

    async def read_body(self, reader: BodyReader, limit_key: str = "max_body_bytes", slack: int = 0) -> bytes:
        """Read the body, enforcing a C-SIZE limit before anything parses it (TH-20).

        `limit_key` names the C-SIZE param (`max_body_bytes`, or `max_artifact_bytes` for
        uploads); `slack` allows for framing around the payload (multipart boundaries).
        Runs after authentication (headers only), so an anonymous caller cannot make the
        gateway read a large body. The policy's action and mode for C-SIZE apply as usual.
        """
        assert self.profile is not None
        cfg = self.policy.level_config(SIZE_CONTROL_ID, self.profile)
        limit = cfg.get(limit_key) if cfg is not None else None
        if cfg is None or limit is None:
            return await reader(None)
        limit = int(limit) + slack
        # A size violation cannot be redacted, so redact behaves like block (as in the engine).
        stops = cfg.mode == "enforce" and cfg.action not in (Action.allow, Action.flag)
        try:
            body = await reader(limit if stops else None)
        except BodyTooLarge as exc:
            decision = _size_decision(cfg.threat_ids, cfg.action, exc.size, limit, shadow=False)
            error = (
                ErrorType.approval_required if cfg.action == Action.require_approval else ErrorType.blocked
            )
            raise GatewayError(error, f"blocked by {SIZE_CONTROL_ID}: {decision.reason}", decision) from exc
        if len(body) > limit:  # flag, or shadow mode: record and continue
            shadow = cfg.mode == "shadow" and cfg.action != Action.allow
            self.extra_decisions.append(_size_decision(cfg.threat_ids, cfg.action, len(body), limit, shadow))
        return body

    def add_stage(self, result: StageResult) -> StageResult:
        self.stages.append(result)
        self.errors += result.errors
        return result

    def decisions(self) -> list[Decision]:
        return self.extra_decisions + [d for s in self.stages for d in s.decisions]

    def final_action(self) -> Action:
        extra = [d.action for d in self.extra_decisions if not d.shadow_suppressed and not d.skipped]
        return strongest_action([s.action for s in self.stages] + extra)

    def would_have_action(self) -> Action | None:
        final = self.final_action()
        candidates = [s.would_have_action for s in self.stages if s.would_have_action is not None]
        candidates += [d.action for d in self.extra_decisions if d.shadow_suppressed]
        strongest = strongest_action(candidates)
        return strongest if candidates and ACTION_PRECEDENCE[strongest] > ACTION_PRECEDENCE[final] else None

    def overhead_ms(self) -> float:
        return (time.perf_counter() - self._t0) * 1000 - self.upstream_ms

    def response_headers(self, action: Action | None) -> dict[str, str]:
        headers = {
            "X-AICL-Request-Id": self.request_id,
            "X-AICL-Policy-Version": self.policy.version,
            "X-AICL-Overhead-Ms": f"{self.overhead_ms():.2f}",
        }
        if action is not None:
            headers["X-AICL-Action"] = action.value
        return headers

    def emit(self, final_action: Action | None, error: str | None = None) -> None:
        per_control: dict[str, float] = {}
        for d in self.decisions():
            per_control[d.control_id] = round(per_control.get(d.control_id, 0.0) + d.latency_ms, 3)
        errors = self.errors + ([error] if error else [])
        self.rt.audit.emit(
            new_event(
                "request",
                request_id=self.request_id,
                session_id=self.session_id,
                endpoint=self.endpoint,
                identity=self.identity.id if self.identity else None,
                role=self.identity.role if self.identity else None,
                profile=self.profile,
                policy_version=self.policy.version,
                feed_version=self.feed_version,
                model=self.model,
                final_action=final_action,
                would_have_action=self.would_have_action(),
                shadow=any(d.shadow_suppressed for d in self.decisions()),
                upstream_called=self.upstream_called,
                decisions=[AuditDecision.from_decision(d) for d in self.decisions()],
                latency_ms=Latency(
                    total_overhead=round(self.overhead_ms(), 3),
                    upstream=round(self.upstream_ms, 3),
                    per_control=per_control,
                ),
                usage=self.usage,
                error="; ".join(errors) or None,
            )
        )

    def fail(self, exc: GatewayError) -> FlowResponse:
        """Audit and answer an error. Blocks count as decisions; other errors are recorded as errors."""
        if exc.decision is not None and all(d is not exc.decision for d in self.decisions()):
            self.extra_decisions.append(exc.decision)  # raised outside the engine (C-AUTH, body size)
        action = _ERROR_ACTION.get(exc.type)
        self.emit(action, error=None if action is not None else exc.message)
        if exc.type == ErrorType.budget_exceeded:
            self.rt.audit.emit(
                new_event(
                    "budget.exceeded",
                    request_id=self.request_id,
                    session_id=self.session_id,
                    endpoint=self.endpoint,
                    identity=self.identity.id if self.identity else None,
                    role=self.identity.role if self.identity else None,
                    policy_version=self.policy.version,
                    detail={
                        "control_id": exc.decision.control_id if exc.decision else None,
                        "reason": exc.message,
                    },
                )
            )
        return FlowResponse(
            status=exc.status,
            body=exc.body(self.request_id).model_dump(mode="json"),
            headers=self.response_headers(action),
        )


def _size_decision(threat_ids: list[str], action: Action, size: int, limit: int, shadow: bool) -> Decision:
    return Decision(
        control_id=SIZE_CONTROL_ID,
        threat_ids=list(threat_ids),
        action=action,
        severity="medium",
        reason=f"request body of {size} bytes exceeds limit of {limit}",
        matches=[Match(kind="body_size_limit", masked=f"{size} bytes")],
        shadow_suppressed=shadow,
    )


def stop_if_blocked(result: StageResult) -> None:
    """Raise when a stage ended in block / require_approval."""
    if not result.stopped:
        return
    assert result.blocking is not None
    d = result.blocking
    if result.action == Action.require_approval:
        raise GatewayError(ErrorType.approval_required, f"approval required by {d.control_id}: {d.reason}", d)
    if d.control_id in _BUDGET_CONTROLS:  # §5.3: budget exceeded is 429, not 403
        raise GatewayError(ErrorType.budget_exceeded, f"budget exceeded ({d.control_id}): {d.reason}", d)
    raise GatewayError(ErrorType.blocked, f"blocked by {d.control_id}: {d.reason}", d)


async def account_usage(rt: Runtime, rec: RequestRecord) -> None:
    """Post stage: usage counters per identity and budget window (§5.5)."""
    if rec.identity is None:
        return
    budget = rec.policy.budget_for(rec.identity.role)
    window = budget.window if budget else "day"
    usage = rec.usage or Usage()
    await rt.state.add_usage(
        rec.identity.id,
        window,
        requests=1,
        prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens,
        cost_usd=usage.cost_usd,
        compute_seconds=usage.compute_seconds,
    )
    if window != "minute":
        # max_requests_per_minute is checked against the minute window, whatever the budget window.
        await rt.state.add_usage(rec.identity.id, "minute", requests=1)


def extract_tool_arg_segments(
    tool_args: Any,
    origin: Origin,
    base_idx: int = 0,
    trust: Trust = "trusted",
    tool_name: str | None = None,
) -> list[Segment]:
    """Turn string values inside tool arguments into Segments for inspection."""
    extracted: list[tuple[list[Any], str]] = []

    def _walk(val: Any, path: list[Any]) -> None:
        if isinstance(val, str):
            if val.strip():
                extracted.append((path, val))
        elif isinstance(val, dict):
            for k, v in val.items():
                _walk(v, path + [k])
        elif isinstance(val, (list, tuple)):
            for i, v in enumerate(val):
                _walk(v, path + [i])

    _walk(tool_args, [])
    segments: list[Segment] = []
    for i, (path, text) in enumerate(extracted):
        meta: dict[str, Any] = {"arg_path": path}
        if tool_name:
            meta["tool"] = tool_name
        segments.append(build_segment(base_idx + i, text, origin, trust, meta))
    return segments


def apply_redacted_args(tool_args: Any, segments: list[Segment]) -> Any:
    """Apply redacted text back into tool_args structure based on meta['arg_path']."""
    import copy

    updated = copy.deepcopy(tool_args)
    for seg in segments:
        path = seg.meta.get("arg_path")
        if path is not None and isinstance(path, list):
            curr = updated
            for p in path[:-1]:
                if isinstance(curr, dict) and p in curr or isinstance(curr, list) and isinstance(p, int) and 0 <= p < len(curr):
                    curr = curr[p]
                else:
                    break
            else:
                if path:
                    last_p = path[-1]
                    if isinstance(curr, dict) and last_p in curr or isinstance(curr, list) and isinstance(last_p, int) and 0 <= last_p < len(curr):
                        curr[last_p] = seg.text
                elif isinstance(updated, str):
                    updated = seg.text
    return updated


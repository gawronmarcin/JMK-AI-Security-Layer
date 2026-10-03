"""Pieces shared by all flows: authentication (C-AUTH), the audit record, responses."""

from __future__ import annotations

import time
from collections.abc import Mapping
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
    Profile,
    Usage,
    strongest_action,
)
from aicl.policy.schema import CompiledPolicy, IdentitySpec
from aicl.runtime import Runtime
from aicl.utils import new_id

AUTH_CONTROL_ID = "C-AUTH"
AUTH_THREATS = ["TH-08"]

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


def authenticate(policy: CompiledPolicy, headers: Mapping[str, str]) -> IdentitySpec:
    """C-AUTH: Bearer key -> identity; a claimed X-AICL-Agent must match that identity."""
    auth = headers.get("authorization", "")
    scheme, _, key = auth.partition(" ")
    identity = policy.identity_for_key(key.strip()) if scheme.lower() == "bearer" and key.strip() else None
    if identity is None:
        raise GatewayError(
            ErrorType.auth_failed, "missing or invalid API key", _auth_decision("unknown API key")
        )
    claimed = headers.get("x-aicl-agent")
    if claimed is not None and claimed != identity.id:
        raise GatewayError(
            ErrorType.auth_failed,
            "X-AICL-Agent does not match the API key's identity",
            _auth_decision("agent id mismatch (impersonation attempt)"),
        )
    return identity


def _auth_decision(reason: str) -> Decision:
    return Decision(
        control_id=AUTH_CONTROL_ID,
        threat_ids=AUTH_THREATS,
        action=Action.block,
        severity="high",
        reason=reason,
    )


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
        self.identity = authenticate(self.policy, self.headers)
        self.profile = self.policy.profile_for(self.identity)
        return self.identity

    def add_stage(self, result: StageResult) -> StageResult:
        self.stages.append(result)
        self.errors += result.errors
        return result

    def decisions(self) -> list[Decision]:
        return self.extra_decisions + [d for s in self.stages for d in s.decisions]

    def final_action(self) -> Action:
        return strongest_action([s.action for s in self.stages])

    def would_have_action(self) -> Action | None:
        final = self.final_action()
        candidates = [s.would_have_action for s in self.stages if s.would_have_action is not None]
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
        if exc.decision is not None and exc.decision.control_id == AUTH_CONTROL_ID:
            self.extra_decisions.append(exc.decision)
        action = _ERROR_ACTION.get(exc.type)
        self.emit(action, error=None if action is not None else exc.message)
        return FlowResponse(
            status=exc.status,
            body=exc.body(self.request_id).model_dump(mode="json"),
            headers=self.response_headers(action),
        )


def stop_if_blocked(result: StageResult) -> None:
    """Raise when a stage ended in block / require_approval."""
    if not result.stopped:
        return
    assert result.blocking is not None
    d = result.blocking
    if result.action == Action.require_approval:
        raise GatewayError(ErrorType.approval_required, f"approval required by {d.control_id}: {d.reason}", d)
    raise GatewayError(ErrorType.blocked, f"blocked by {d.control_id}: {d.reason}", d)

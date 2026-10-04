"""Core data contracts shared by every part of AICL.

CONTRACT (ARCHITECTURE.md §4, §5.3, §8): field names and meanings are binding for
all roles. Change only with team agreement, in the same commit as ARCHITECTURE.md.

Flow: the engine builds a RequestContext, every control turns it into a Decision,
the engine merges decisions and writes one AuditEvent per request.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from aicl.policy.schema import ControlLevelConfig


class _Model(BaseModel):
    # Typos in field names must fail loudly, not be silently ignored.
    model_config = ConfigDict(extra="forbid")


# --- Enums and literal types ---------------------------------------------------------------


class Stage(str, Enum):
    ingress = "ingress"
    input = "input"
    tool_call = "tool_call"
    tool_result = "tool_result"
    output = "output"
    artifact = "artifact"


class Action(str, Enum):
    # Declared in precedence order, highest first (see ACTION_PRECEDENCE).
    block = "block"
    require_approval = "require_approval"
    redact = "redact"
    flag = "flag"
    allow = "allow"


class Origin(str, Enum):
    system = "system"
    user = "user"
    assistant = "assistant"
    tool_result = "tool_result"
    retrieved = "retrieved"
    artifact = "artifact"


Trust = Literal["trusted", "untrusted"]
Severity = Literal["low", "medium", "high", "critical"]
Endpoint = Literal["chat", "tool_invoke", "mcp", "artifact_scan"]
Profile = Literal["strict", "balanced", "permissive"]

ACTION_PRECEDENCE: dict[Action, int] = {
    Action.block: 4,
    Action.require_approval: 3,
    Action.redact: 2,
    Action.flag: 1,
    Action.allow: 0,
}

SEVERITY_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def strongest_action(actions: list[Action]) -> Action:
    """Highest-precedence action; `allow` for an empty list."""
    return max(actions, key=ACTION_PRECEDENCE.__getitem__, default=Action.allow)


# --- Request context (input to every control) -----------------------------------------------


class Segment(_Model):
    """One piece of text a control looks at: a message, a tool result, a retrieved doc.

    Views: `text` is the original (redaction offsets refer to it), `norm` is normalized
    and casefolded, `decoded` holds text recovered from base64/hex/url/rot13 fragments
    (not casefolded). Each control picks the views it matches on (§5.2).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    idx: int
    text: str = Field(repr=False)
    norm: str = Field(repr=False)
    decoded: list[str] = Field(default_factory=list, repr=False)
    origin: Origin
    trust: Trust = "trusted"
    meta: dict[str, Any] = Field(default_factory=dict)


class RequestContext(_Model):
    """Everything known about the request at a given stage. Controls must not mutate it;
    the engine derives new versions with `ctx.model_copy(update=...)`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    session_id: str
    endpoint: Endpoint
    stage: Stage
    identity: str | None
    role: str | None
    profile: Profile
    model: str | None
    segments: list[Segment]
    tool: str | None = None
    tool_args: dict[str, Any] | None = Field(default=None, repr=False)
    artifact: bytes | None = Field(default=None, repr=False)
    risk: float = 0.0
    tainted: bool = False
    policy_version: str


# --- Control output ----------------------------------------------------------------------------


class Match(_Model):
    kind: str
    segment_idx: int | None = None
    start: int | None = None  # offsets into Segment.text
    end: int | None = None
    masked: str | None = None  # masked excerpt, NEVER the raw value
    in_decoded: bool = False  # found only in decoded text: no span, cannot be redacted


class Decision(_Model):
    control_id: str
    threat_ids: list[str]
    action: Action
    severity: Severity = "low"
    score: float | None = None
    reason: str = ""
    matches: list[Match] = Field(default_factory=list)
    risk: float | None = None  # contribution to ctx.risk; the engine keeps the max
    taints_session: bool = False
    latency_ms: float = 0.0  # filled by the engine
    skipped: bool = False
    shadow_suppressed: bool = False
    retry_after_s: float | None = None


@runtime_checkable
class Control(Protocol):
    """A control evaluates a context and returns a Decision. It never raises for policy
    violations, never mutates ctx and never writes logs (§4.1)."""

    id: str
    stages: tuple[Stage, ...]
    priority: int  # lower runs first; cheap deterministic < 100, semantic >= 500

    async def evaluate(self, ctx: RequestContext, cfg: ControlLevelConfig) -> Decision: ...


# --- Audit event (§8) -------------------------------------------------------------------------

EventType = Literal[
    "request", "policy.reloaded", "policy.rejected", "feed.reloaded", "feed.rejected", "budget.exceeded",
    "config.warning",
    # HITL (aicl/approvals.py): a request needs approval / an approval was used or refused
    "approval.requested", "approval.decided", "approval.used", "approval.refused",
]


class AuditMatch(_Model):
    """Match as logged: masked excerpt only, no offsets."""

    kind: str
    segment_idx: int | None = None
    masked: str | None = None


class AuditDecision(_Model):
    control_id: str
    threat_ids: list[str]
    action: Action
    severity: Severity = "low"
    score: float | None = None
    reason: str = ""
    matches: list[AuditMatch] = Field(default_factory=list)
    latency_ms: float = 0.0
    skipped: bool = False
    shadow_suppressed: bool = False

    @classmethod
    def from_decision(cls, d: Decision) -> AuditDecision:
        return cls(
            control_id=d.control_id,
            threat_ids=d.threat_ids,
            action=d.action,
            severity=d.severity,
            score=d.score,
            reason=d.reason,
            matches=[AuditMatch(kind=m.kind, segment_idx=m.segment_idx, masked=m.masked) for m in d.matches],
            latency_ms=d.latency_ms,
            skipped=d.skipped,
            shadow_suppressed=d.shadow_suppressed,
        )


class Usage(_Model):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    compute_seconds: float = 0.0


class Latency(_Model):
    total_overhead: float = 0.0
    upstream: float = 0.0
    per_control: dict[str, float] = Field(default_factory=dict)


class AuditEvent(_Model):
    """One line of audit.jsonl. Request fields stay null for non-request event types;
    those carry their payload in `detail` (e.g. the validation error of a rejected policy)."""

    ts: str
    event_id: str
    type: EventType
    request_id: str | None = None
    session_id: str | None = None
    endpoint: Endpoint | None = None
    identity: str | None = None
    role: str | None = None
    profile: Profile | None = None
    policy_version: str | None = None
    feed_version: str | None = None
    model: str | None = None
    final_action: Action | None = None
    would_have_action: Action | None = None
    shadow: bool = False
    upstream_called: bool = False
    decisions: list[AuditDecision] = Field(default_factory=list)
    latency_ms: Latency | None = None
    usage: Usage | None = None
    error: str | None = None
    detail: dict[str, Any] | None = None


# --- Error contract (§5.3) --------------------------------------------------------------------


class ErrorType(str, Enum):
    auth_failed = "aicl_auth_failed"
    blocked = "aicl_blocked"
    approval_required = "aicl_approval_required"
    budget_exceeded = "aicl_budget_exceeded"
    bad_request = "aicl_bad_request"
    upstream_error = "aicl_upstream_error"


ERROR_STATUS: dict[ErrorType, int] = {
    ErrorType.auth_failed: 401,
    ErrorType.blocked: 403,
    ErrorType.approval_required: 403,
    ErrorType.budget_exceeded: 429,
    ErrorType.bad_request: 400,
    ErrorType.upstream_error: 502,
}


class ErrorDetail(_Model):
    type: ErrorType
    message: str
    threat_ids: list[str] = Field(default_factory=list)
    control_id: str | None = None
    request_id: str | None = None
    approval_id: str | None = None


class ErrorBody(_Model):
    error: ErrorDetail

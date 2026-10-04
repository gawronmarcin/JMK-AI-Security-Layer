"""Pieces shared by all flows: authentication (C-AUTH), the audit record, responses."""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from aicl.audit import new_event
from aicl.controls.delegation import delegated_depth
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
from aicl.utils import new_id, stable_hash

AUTH_CONTROL_ID = "C-AUTH"
AUTH_THREATS = ["TH-08"]
SIZE_CONTROL_ID = "C-SIZE"
# Blocks by these controls are answered as 429 aicl_budget_exceeded (§5.3).
_BUDGET_CONTROLS = frozenset({"C-BUDGET"})
DELEGATION_TICKET_HEADER = "x-aicl-delegation-ticket"


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
    """C-AUTH: Bearer key -> identity; a claimed X-AICL-Agent must match that identity.

    `AICL_ADMIN_OPEN=1` opens the /admin endpoints only (aicl/admin/*); the gateway API always
    needs a key, otherwise an anonymous caller would act as `admin` (every tool, no budget).
    `env` is kept for callers that pass it.
    """
    auth = headers.get("authorization", "")
    scheme, _, key = auth.partition(" ")
    identity = policy.identity_for_key(key.strip()) if scheme.lower() == "bearer" and key.strip() else None
    claimed = headers.get("x-aicl-agent")

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
    # session_id is the state key "<identity>:<client session id>" once authenticated, so one
    # identity can neither taint nor read another identity's session (C-TAINT, C-LOOP, C-DELEG)
    session_id: str = field(init=False)
    client_session_id: str = field(init=False)
    identity: IdentitySpec | None = None
    profile: Profile | None = None
    model: str | None = None
    stages: list[StageResult] = field(default_factory=list)
    extra_decisions: list[Decision] = field(default_factory=list)
    upstream_called: bool = False
    upstream_ms: float = 0.0
    usage: Usage | None = None
    errors: list[str] = field(default_factory=list)
    # HITL: stages whose require_approval was satisfied by an operator approval, and its details
    approved_stages: set[int] = field(default_factory=set)
    approval: dict[str, Any] | None = None
    notes: dict[str, Any] = field(default_factory=dict)  # extra facts for the audit event `detail`
    _t0: float = field(default_factory=time.perf_counter)

    def __post_init__(self) -> None:
        # One snapshot of policy and feed per request, even if they are reloaded meanwhile.
        self.policy = self.rt.policy
        self.feed_version = self.rt.feeds.current().version
        self.client_session_id = self.headers.get("x-aicl-session") or new_id("sess")
        self.session_id = self.client_session_id  # until authenticated (audit of auth failures)

    def authenticate(self) -> IdentitySpec:
        self.identity = authenticate(self.policy, self.headers, getattr(self.rt, "env", None))
        self.profile = self.policy.profile_for(self.identity)
        self.use_session(self.client_session_id)
        return self.identity

    def use_session(self, client_session_id: str) -> None:
        """Bind the client's session id to the authenticated identity."""
        assert self.identity is not None, "authenticate() first"
        self.client_session_id = client_session_id
        self.session_id = f"{self.identity.id}:{client_session_id}"

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

    async def join_delegation(self) -> None:
        """A sub-agent's request with `X-AICL-Delegation-Ticket` (issued when a delegation went
        through, see `issue_delegation_ticket`) puts its session at the delegated depth and
        carries the parent session's taint over (C-DELEG, C-TAINT). A ticket only ever adds
        restrictions, so an unknown or reused one gains nothing."""
        ticket = self.headers.get(DELEGATION_TICKET_HEADER)
        if not ticket:
            return
        parent = await self.rt.state.get_session(f"dlg:{ticket}")
        own = await self.rt.state.get_session(self.session_id)
        if parent.delegation_depth > own.delegation_depth:
            await self.rt.state.set_delegation_depth(self.session_id, parent.delegation_depth)
        if parent.tainted:
            await self.rt.state.mark_tainted(self.session_id, "delegation")
        self.notes["delegation_ticket"] = ticket

    def check_message_sizes(self, n_messages: int, lengths: list[int]) -> None:
        """C-SIZE `max_messages` / `max_chars_per_message` before the segments are built: the
        normalization of a huge message is itself the cost to avoid (TH-20).

        Only a block fails fast here (redact counts as block, as in the engine). Flag, shadow and
        require_approval are left to the C-SIZE control at ingress, so nothing is recorded twice.
        """
        assert self.profile is not None
        cfg = self.policy.level_config(SIZE_CONTROL_ID, self.profile)
        if cfg is None or cfg.mode != "enforce" or cfg.action not in (Action.block, Action.redact):
            return
        max_messages, max_chars = cfg.get("max_messages"), cfg.get("max_chars_per_message")
        if max_messages is not None and n_messages > int(max_messages):
            reason = f"message count {n_messages} exceeds limit of {max_messages}"
            match = Match(kind="message_count_limit", masked=f"{n_messages} messages")
        else:
            over = next(((i, n) for i, n in enumerate(lengths) if n > int(max_chars)), None) if max_chars else None
            if over is None:
                return
            reason = f"message[{over[0]}] length {over[1]} chars exceeds limit of {max_chars}"
            match = Match(kind="message_length_limit", segment_idx=over[0], masked=f"{over[1]} chars")
        decision = Decision(control_id=SIZE_CONTROL_ID, threat_ids=list(cfg.threat_ids), action=Action.block,
                            severity="medium", reason=reason, matches=[match])
        raise GatewayError(ErrorType.blocked, f"blocked by {SIZE_CONTROL_ID}: {reason}", decision)

    def add_stage(self, result: StageResult) -> StageResult:
        self.stages.append(result)
        self.errors += result.errors
        return result

    def decisions(self) -> list[Decision]:
        return self.extra_decisions + [d for s in self.stages for d in s.decisions]

    def final_action(self) -> Action:
        extra = [d.action for d in self.extra_decisions if not d.shadow_suppressed and not d.skipped]
        return strongest_action([self._stage_action(s) for s in self.stages] + extra)

    def _stage_action(self, stage: StageResult) -> Action:
        """A stage's action; an operator-approved stage counts without its require_approval."""
        if id(stage) not in self.approved_stages:
            return stage.action
        return strongest_action([d.action for d in stage.decisions
                                 if d.action != Action.require_approval and not d.skipped
                                 and not d.shadow_suppressed])

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
            "X-AICL-Session": self.client_session_id,
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
                detail=({**self.notes, **({"approval": self.approval} if self.approval else {})} or None),
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
        headers = self.response_headers(action)
        if exc.type == ErrorType.budget_exceeded and exc.decision and exc.decision.retry_after_s is not None:
            import math
            headers["Retry-After"] = str(math.ceil(exc.decision.retry_after_s))
        return FlowResponse(
            status=exc.status,
            body=exc.body(self.request_id).model_dump(mode="json"),
            headers=headers,
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


def approval_subject(result: StageResult, subject: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """What an approval authorizes: the stage plus the action (`subject`, e.g. tool + arguments as
    the client sent them, NOT after redaction: two recipients redacted to the same placeholder
    must not share one approval), or the stage's texts when the caller has no better description."""
    if subject is not None:
        return {"stage": result.stage.value, **subject}
    return {"stage": result.stage.value, "texts": [seg.text for seg in result.segments]}


def _preview(value: Any, limit: int = 120) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _approval_summary(subject: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    """Operator view of the action: one line + a preview with truncated values. It shows the real
    arguments (the operator must see who an e-mail goes to); it is served by the admin API only
    and kept in memory - the audit log gets the fingerprint, not this."""
    if "tool" in subject:
        args = subject.get("args")
        shown = args if isinstance(args, Mapping) else {"_value": args}
        preview = {str(k): _preview(v) for k, v in shown.items()}
        inner = ", ".join(f"{k}={_preview(v, 40)}" for k, v in preview.items())
        return f"{subject['tool']}({inner})", {"stage": subject.get("stage"), "tool": subject["tool"], "args": preview}
    texts = [_preview(t) for t in subject.get("texts", [])]
    first = texts[0] if texts else ""
    more = f" (+{len(texts) - 1} more)" if len(texts) > 1 else ""
    return f"{subject.get('stage')}: {first}{more}", {"stage": subject.get("stage"), "texts": texts}


def _emit_approval_event(rec: RequestRecord, kind: str, detail: dict[str, Any]) -> None:
    rec.rt.audit.emit(
        new_event(
            kind,  # type: ignore[arg-type]  # one of the approval.* EventType values
            request_id=rec.request_id,
            session_id=rec.session_id,
            endpoint=rec.endpoint,
            identity=rec.identity.id if rec.identity else None,
            role=rec.identity.role if rec.identity else None,
            policy_version=rec.policy.version,
            detail=detail,
        )
    )


def stop_if_blocked(
    result: StageResult, rec: RequestRecord | None = None, subject: Mapping[str, Any] | None = None
) -> None:
    """Raise when a stage ended in block / require_approval.

    require_approval: an `X-AICL-Approval-Id` approved by an operator lets the request through
    only if it was granted to this identity for this exact action (fingerprint of endpoint,
    control and `approval_subject`), has not expired and was not used before (aicl/approvals.py).
    Otherwise the pending approval for this action is (re)used and its id returned.
    """
    if not result.stopped:
        return
    assert result.blocking is not None
    d = result.blocking
    if result.action == Action.require_approval:
        approval_id = None
        message = f"approval required by {d.control_id}: {d.reason}"
        if rec is not None:
            identity = rec.identity.id if rec.identity else None
            subj = approval_subject(result, subject)
            fingerprint = stable_hash({"endpoint": rec.endpoint, "control_id": d.control_id, "subject": subj})
            claimed = rec.headers.get("x-aicl-approval-id") or rec.headers.get("x-aicl-approval")
            if claimed:
                ok, why = rec.rt.approvals.consume(
                    claimed, identity=identity, fingerprint=fingerprint, request_id=rec.request_id
                )
                event = {"approval_id": claimed, "control_id": d.control_id, "fingerprint": fingerprint,
                         "result": "used" if ok else "refused", "reason": why}
                _emit_approval_event(rec, "approval.used" if ok else "approval.refused", event)
                if ok:
                    item = rec.rt.approvals.get(claimed)
                    rec.approved_stages.add(id(result))
                    rec.approval = {"approval_id": claimed, "control_id": d.control_id,
                                    "decided_by": item.decided_by if item else None}
                    return
                message += f" (approval {claimed} not accepted: {why})"
            appr = rec.rt.approvals.find_pending(identity, fingerprint)
            if appr is None:
                summary, preview = _approval_summary(subj)
                appr = rec.rt.approvals.create(
                    request_id=rec.request_id,
                    session_id=rec.session_id,
                    control_id=d.control_id,
                    threat_ids=d.threat_ids,
                    reason=d.reason,
                    identity=identity,
                    action_type=rec.endpoint,
                    payload=preview,
                    fingerprint=fingerprint,
                    summary=summary,
                )
                _emit_approval_event(rec, "approval.requested", {
                    "approval_id": appr.approval_id, "control_id": d.control_id, "fingerprint": fingerprint})
            approval_id = appr.approval_id
        raise GatewayError(ErrorType.approval_required, message, d, approval_id=approval_id)
    if d.control_id in _BUDGET_CONTROLS:  # §5.3: budget exceeded is 429, not 403
        raise GatewayError(ErrorType.budget_exceeded, f"budget exceeded ({d.control_id}): {d.reason}", d)
    raise GatewayError(ErrorType.blocked, f"blocked by {d.control_id}: {d.reason}", d)


async def issue_delegation_ticket(rt: Runtime, rec: RequestRecord, args: Mapping[str, Any]) -> str:
    """After a delegation tool call went through: a ticket for the sub-agent, holding the depth of
    the delegated task and the caller session's taint. The sub-agent sends it back as
    `X-AICL-Delegation-Ticket` (RequestRecord.join_delegation)."""
    session = await rt.state.get_session(rec.session_id)
    ticket = new_id("dlg")
    key = f"dlg:{ticket}"
    await rt.state.set_delegation_depth(key, delegated_depth(session.delegation_depth, args))
    if session.tainted:
        await rt.state.mark_tainted(key, "delegation")
    rec.notes["delegation_ticket_issued"] = ticket
    return ticket


def fail_closed_redaction(result: StageResult, where: str) -> None:
    """A redaction the flow cannot write back into the request/response (e.g. text decoded from
    a data: URL) is turned into a block, as the engine does for spans found only in decoded text."""
    d = next(
        (d for d in result.decisions if d.action == Action.redact and not d.shadow_suppressed and not d.skipped),
        None,
    )
    if d is None:
        return
    reason = f"{d.reason} (in {where}, which cannot be redacted in place: failing closed)"
    decision = d.model_copy(update={"action": Action.block, "reason": reason})
    raise GatewayError(ErrorType.blocked, f"blocked by {d.control_id}: {reason}", decision)


async def account_usage(rt: Runtime, rec: RequestRecord) -> None:
    """Post stage: usage counters per identity and budget window (§5.5)."""
    if rec.identity is None:
        return
    budget = rec.policy.budget_for(rec.identity.role)
    window = budget.window if budget else "day"
    usage = rec.usage or Usage()

    settled = await rt.state.settle(
        rec.request_id,
        prompt_tokens=usage.prompt_tokens,
        completion_tokens=usage.completion_tokens,
        cost_usd=usage.cost_usd,
        compute_seconds=usage.compute_seconds,
    )
    if not settled:
        if any(d.control_id in _BUDGET_CONTROLS and d.action == Action.block for d in rec.decisions()):
            return
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


def string_leaves(value: Any) -> list[tuple[list[Any], str]]:
    """(path, text) of every non-blank string inside nested dicts and lists, in document order."""
    leaves: list[tuple[list[Any], str]] = []

    def _walk(val: Any, path: list[Any]) -> None:
        if isinstance(val, str):
            if val.strip():
                leaves.append((path, val))
        elif isinstance(val, dict):
            for k, v in val.items():
                _walk(v, path + [k])
        elif isinstance(val, (list, tuple)):
            for i, v in enumerate(val):
                _walk(v, path + [i])

    _walk(value, [])
    return leaves


_DESCRIPTION_KEYS = frozenset({"description", "title"})


def description_leaves(value: Any, path: list[Any]) -> list[tuple[list[Any], str]]:
    """`description` / `title` strings anywhere in a tool definition (JSON schema included)."""
    return [
        (path + p, text) for p, text in string_leaves(value)
        if p and isinstance(p[-1], str) and p[-1] in _DESCRIPTION_KEYS
    ]


def extract_tool_arg_segments(
    tool_args: Any,
    origin: Origin,
    base_idx: int = 0,
    trust: Trust = "trusted",
    tool_name: str | None = None,
) -> list[Segment]:
    """Turn string values inside tool arguments into Segments for inspection."""
    segments: list[Segment] = []
    for i, (path, text) in enumerate(string_leaves(tool_args)):
        meta: dict[str, Any] = {"arg_path": path}
        if tool_name:
            meta["tool"] = tool_name
        segments.append(build_segment(base_idx + i, text, origin, trust, meta))
    return segments


def keep_args(redacted: Any, original: Any, names: list[str]) -> Any:
    """Put back the original value of top-level arguments listed in the tool's `no_redact_args`."""
    if not names or not isinstance(redacted, dict) or not isinstance(original, dict):
        return redacted
    return {**redacted, **{k: original[k] for k in names if k in original}}


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


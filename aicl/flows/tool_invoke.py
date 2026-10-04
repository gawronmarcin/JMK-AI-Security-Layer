"""POST /v1/tools/invoke (§1.2, §5.1):

    C-AUTH -> ingress -> tool_call -> backend -> tool_result -> post

Stages:
  1. ingress: C-AUTH (api key), body size limit (C-SIZE), budget check (C-BUDGET)
  2. tool_call: tool authorization (C-TOOL-ACL), loop guard (C-LOOP), taint guard (C-TAINT)
  3. forward: HTTP POST to tool backend
  4. tool_result: scan output for PII/secrets/injection (C-PII-OUT, C-SECRET-OUT, C-INJ-PAT/C-INJ-SEM);
     mark session tainted if tool has output_trust == "untrusted"
  5. post: accounting (requests, compute_seconds) -> audit event
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aicl.controls.delegation import DELEGATION_TOOLS
from aicl.engine import run_stage
from aicl.errors import GatewayError
from aicl.flows.common import (
    BodyReader,
    FlowResponse,
    RequestRecord,
    account_usage,
    apply_redacted_args,
    auth_decision,
    extract_tool_arg_segments,
    fail_closed_redaction,
    issue_delegation_ticket,
    keep_args,
    stop_if_blocked,
    string_leaves,
)
from aicl.models import Action, ErrorType, Origin, RequestContext, Segment, Stage, Trust, Usage
from aicl.normalize import build_segment
from aicl.proxy import UpstreamError
from aicl.runtime import Runtime


class ToolInvokeRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    tool: str
    arguments: dict[str, Any] | Any = Field(default_factory=dict)
    session_id: str | None = None
    caller_agent: str | None = None


MAX_RESULT_SEGMENTS = 200  # strings of one tool result inspected (and redactable) one by one


def _result_segments(body: dict[str, Any], tool: str, trust: Trust) -> list[Segment]:
    """One segment per string in the tool result (meta `arg_path` locates it for redaction).

    Shortest first, so the longest texts get the highest idx: the semantic judge looks at the
    last segments first and caps how many it judges. Past MAX_RESULT_SEGMENTS the shortest
    strings are joined into one `overflow` segment: inspected, but a redaction there blocks.
    """
    leaves = sorted(string_leaves(body), key=lambda leaf: len(leaf[1]))
    overflow: list[tuple[list[Any], str]] = []
    if len(leaves) > MAX_RESULT_SEGMENTS:
        cut = len(leaves) - (MAX_RESULT_SEGMENTS - 1)
        overflow, leaves = leaves[:cut], leaves[cut:]
    segments = []
    if overflow:
        text = "\n".join(t for _, t in overflow)
        segments.append(build_segment(0, text, Origin.tool_result, trust, {"tool": tool, "overflow": True}))
    for path, text in leaves:
        meta = {"tool": tool, "arg_path": path}
        segments.append(build_segment(len(segments), text, Origin.tool_result, trust, meta))
    return segments


def _parse(raw: bytes) -> tuple[ToolInvokeRequest, dict[str, Any]]:
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise GatewayError(ErrorType.bad_request, "body is not valid JSON") from exc
    if not isinstance(data, dict):
        raise GatewayError(ErrorType.bad_request, "body must be a JSON object")
    try:
        return ToolInvokeRequest.model_validate(data), data
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(p) for p in first["loc"])
        raise GatewayError(ErrorType.bad_request, f"{loc}: {first['msg']}") from exc


async def handle_tool_invoke(rt: Runtime, read_body: BodyReader, headers: Mapping[str, str]) -> FlowResponse:
    rec = RequestRecord(rt=rt, endpoint="tool_invoke", headers=headers)
    try:
        return await _run(rt, rec, read_body, headers)
    except GatewayError as exc:
        return rec.fail(exc)
    finally:
        await account_usage(rt, rec)


async def _run(
    rt: Runtime, rec: RequestRecord, read_body: BodyReader, headers: Mapping[str, str]
) -> FlowResponse:
    policy = rec.policy
    identity = rec.authenticate()
    req, _ = _parse(await rec.read_body(read_body))
    if req.session_id:
        rec.use_session(req.session_id)
    await rec.join_delegation()
    if req.caller_agent is not None and req.caller_agent != identity.id:
        raise GatewayError(
            ErrorType.auth_failed,
            "caller_agent does not match the API key's identity",
            auth_decision("caller_agent mismatch (impersonation attempt)"),
        )

    args = (
        req.arguments
        if isinstance(req.arguments, dict)
        else ({} if req.arguments is None else {"_value": req.arguments})
    )
    assert rec.profile is not None

    session = await rt.state.get_session(rec.session_id)

    ctx = RequestContext(
        request_id=rec.request_id,
        session_id=rec.session_id,
        endpoint="tool_invoke",
        stage=Stage.ingress,
        identity=identity.id,
        role=identity.role,
        profile=rec.profile,
        model=None,
        segments=[],
        tool=req.tool,
        tool_args=args,
        tainted=session.tainted,
        policy_version=policy.version,
    )

    # 1. Ingress stage (auth is done, C-BUDGET rate/token check, C-SIZE check)
    stop_if_blocked(rec.add_stage(await run_stage(policy, ctx, Stage.ingress, rt.controls)), rec)

    # 2. Input stage (scan arguments for C-SECRET-IN, C-PII-IN, C-INJ-PAT, C-INJ-SEM)
    requested_args = args  # as sent by the client: what an operator approval is bound to
    arg_segments = extract_tool_arg_segments(args, origin=Origin.user, tool_name=req.tool)
    if arg_segments:
        input_ctx = ctx.model_copy(update={"stage": Stage.input, "segments": arg_segments})
        input_result = rec.add_stage(await run_stage(policy, input_ctx, Stage.input, rt.controls))
        stop_if_blocked(input_result, rec)
        if input_result.action == Action.redact:
            args = apply_redacted_args(args, input_result.segments)
            spec = policy.raw.tools.get(req.tool)
            args = keep_args(args, requested_args, spec.no_redact_args if spec else [])

    # 3. Tool call stage (C-TOOL-ACL, C-LOOP, C-TAINT, C-CANARY, C-CODE-EXEC, C-MEM-ACL)
    call_ctx = ctx.model_copy(update={"stage": Stage.tool_call, "segments": arg_segments, "tool_args": args})
    stop_if_blocked(rec.add_stage(await run_stage(policy, call_ctx, Stage.tool_call, rt.controls)), rec,
                    subject={"tool": req.tool, "args": requested_args})

    # Verify tool exists in policy definition
    tool_spec = policy.raw.tools.get(req.tool)
    if tool_spec is None:
        raise GatewayError(ErrorType.bad_request, f"unknown tool {req.tool!r}")

    # 3. Forward to tool backend
    try:
        upstream = await rt.upstream.invoke_tool(tool_spec, req.tool, args, headers)
    except UpstreamError as exc:
        raise GatewayError(ErrorType.upstream_error, str(exc)) from exc
    rec.upstream_called = True
    rec.upstream_ms = upstream.latency_ms
    body = dict(upstream.body)

    rec.usage = Usage(
        prompt_tokens=0,
        completion_tokens=0,
        cost_usd=0.0,
        compute_seconds=round(upstream.latency_ms / 1000, 3),
    )

    # 4. Tool result stage (C-PII-OUT, C-SECRET-OUT, C-INJ-PAT, C-INJ-SEM): every string in the
    # backend's JSON is inspected, not only `output`/`result`; everything goes back to the client
    trust: Trust = tool_spec.output_trust
    result_segments = _result_segments(body, req.tool, trust)

    res_ctx = ctx.model_copy(update={"stage": Stage.tool_result, "segments": result_segments})
    result = rec.add_stage(await run_stage(policy, res_ctx, Stage.tool_result, rt.controls))
    stop_if_blocked(result, rec)

    # Mark session tainted if tool output is untrusted or if a control marked it
    if trust == "untrusted" or result.taints_session:
        await rt.state.mark_tainted(rec.session_id, f"tool:{req.tool}")

    if result.action == Action.redact:
        changed = [s for s in result.segments if s.text != result_segments[s.idx].text]
        if any(s.meta.get("overflow") for s in changed):
            fail_closed_redaction(result, "a tool result with too many fields")
        body = apply_redacted_args(body, changed)

    headers_out: dict[str, str] = {}
    if req.tool in DELEGATION_TOOLS:
        # the sub-agent joins the delegation with this ticket: depth and taint follow it (C-DELEG)
        ticket = await issue_delegation_ticket(rt, rec, args)
        body["delegation_ticket"] = ticket
        headers_out["X-AICL-Delegation-Ticket"] = ticket

    final = rec.final_action()
    rec.emit(final)
    if "tool" not in body:
        body["tool"] = req.tool
    return FlowResponse(status=200, body=body, headers=rec.response_headers(final) | headers_out)

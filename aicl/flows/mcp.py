"""POST /mcp/{server}: MCP proxy (Streamable HTTP transport, JSON-RPC 2.0, protocol 2025-06-18).

An agent points its MCP client at the gateway instead of the MCP server:

    agent --(MCP, Bearer <AICL key>)--> /mcp/docs --(MCP)--> mcp_servers.docs (policy)

The gateway is an MCP server to the agent and an MCP client of the upstream (aicl/proxy/mcp.py).
It offers the `tools` capability only; resources, prompts, sampling etc. are not proxied
(-32601 method not found), which keeps every action on the governed tools path.

  initialize       answered by the gateway; issues the `Mcp-Session-Id` (= AICL session, bound to
                   the caller's identity like X-AICL-Session)
  ping             {}
  tools/list       upstream list -> default deny: only tools declared in the policy as
                   "<server>.<tool>" AND permitted for the caller's role are shown; descriptions
                   and input-schema text are scanned like any third-party text (tool poisoning):
                   a flagged tool is hidden, a redaction is applied
  tools/call       the same pipeline as /v1/tools/invoke (aicl/flows/tool_invoke.govern_tool_call):
                   argument scan, C-TOOL-ACL/C-LOOP/C-TAINT/..., upstream tools/call, result scan,
                   taint. A block / approval / budget stop is answered as a tool result with
                   isError: true (the agent's model sees why) and the AICL error in _meta.aicl.
  notifications    202 Accepted, no body

Auth failures are HTTP 401 with a JSON-RPC error (-32001). Operator approvals work as for REST:
retry the same call with `X-AICL-Approval-Id`. Audit: tools/list and tools/call are audit events
with endpoint "mcp"; detail.mcp holds the server, method and the hidden tools.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from aicl.engine import run_stage
from aicl.errors import GatewayError
from aicl.flows.common import (
    BodyReader,
    RequestRecord,
    account_usage,
    description_leaves,
    stop_if_blocked,
)
from aicl.flows.tool_invoke import forward_tool, govern_tool_call
from aicl.models import Action, ErrorType, Origin, RequestContext, Stage
from aicl.normalize import build_segment
from aicl.policy.schema import McpServerSpec, ToolSpec
from aicl.proxy import UpstreamError, UpstreamResponse
from aicl.proxy.mcp import PROTOCOL_VERSION, SUPPORTED_VERSIONS, McpUpstreamError
from aicl.runtime import Runtime
from aicl.utils import new_id

PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603
AUTH_ERROR, POLICY_ERROR = -32001, -32002  # implementation-defined server errors

# ErrorTypes that are policy outcomes: answered as a tool result the model can read
_POLICY_STOPS = (ErrorType.blocked, ErrorType.approval_required, ErrorType.budget_exceeded)


@dataclass
class McpResponse:
    status: int
    body: dict[str, Any] | None  # None: 202 Accepted without a body
    headers: dict[str, str] = field(default_factory=dict)


def _error(msg_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": msg_id, "error": err}


def _result(msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _stopped_tool_result(error: dict[str, Any]) -> dict[str, Any]:
    """A policy stop as a CallToolResult: the agent's model sees the reason and can adapt."""
    text = f"Blocked by AI Control Layer: {error.get('message')}"
    if error.get("approval_id"):
        text += (f" An operator must approve it (approval_id {error['approval_id']}); "
                 "retry the same call with header X-AICL-Approval-Id.")
    return {"content": [{"type": "text", "text": text}], "isError": True, "_meta": {"aicl": error}}


async def handle_mcp(rt: Runtime, server: str, read_body: BodyReader, headers: Mapping[str, str]) -> McpResponse:
    rec = RequestRecord(rt=rt, endpoint="mcp", headers=headers)
    governed = False  # tools/list and tools/call: audited and counted against budgets
    msg_id: Any = None
    try:
        try:
            rec.authenticate()
        except GatewayError as exc:
            body = rec.fail(exc).body["error"]
            return McpResponse(401, _error(None, AUTH_ERROR, body["message"], {"aicl": body}),
                               {"WWW-Authenticate": "Bearer"})
        spec = rec.policy.raw.mcp_servers.get(server)
        if spec is None:
            return McpResponse(404, _error(None, INVALID_REQUEST, f"unknown MCP server {server!r}"))
        try:
            msg = json.loads(await rec.read_body(read_body))
        except GatewayError as exc:  # C-SIZE: body over the limit
            rec.fail(exc)
            return McpResponse(413, _error(None, INVALID_REQUEST, exc.message))
        except ValueError:
            return McpResponse(400, _error(None, PARSE_ERROR, "parse error: body is not JSON"))
        if isinstance(msg, list):
            return McpResponse(400, _error(None, INVALID_REQUEST, "JSON-RPC batches are not supported"))
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            return McpResponse(400, _error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message"))

        method = msg.get("method")
        if "id" not in msg or not isinstance(method, str):
            return McpResponse(202, None)  # notification, or a response to a server request
        msg_id = msg["id"]
        params = msg.get("params") or {}
        if not isinstance(params, dict):
            return McpResponse(400, _error(msg_id, INVALID_PARAMS, "params must be an object"))

        if method == "initialize":
            session = new_id("mcp")
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_VERSIONS else PROTOCOL_VERSION
            result = {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": f"aicl/{server}", "version": "0.2.0"},
                "instructions": "Tools are proxied through AI Control Layer: calls and results are "
                                "inspected and may be blocked or redacted by policy.",
            }
            return McpResponse(200, _result(msg_id, result), {"Mcp-Session-Id": session})
        if method == "ping":
            return McpResponse(200, _result(msg_id, {}))
        if method not in ("tools/list", "tools/call"):
            return McpResponse(200, _error(msg_id, METHOD_NOT_FOUND, f"method {method!r} is not available "
                                                                      "through AI Control Layer (tools only)"))

        client_session = headers.get("mcp-session-id") or headers.get("x-aicl-session")
        if client_session:
            rec.use_session(client_session)
        await rec.join_delegation()
        governed = True
        rec.notes["mcp"] = {"server": server, "method": method}
        if method == "tools/list":
            return await _tools_list(rt, rec, server, spec, msg_id, params)
        return await _tools_call(rt, rec, server, msg_id, params, headers)
    finally:
        if governed:
            await account_usage(rt, rec)


def _response_headers(rec: RequestRecord, action: Action | None) -> dict[str, str]:
    h = rec.response_headers(action)
    h["Mcp-Session-Id"] = rec.client_session_id
    return h


async def _tools_list(
    rt: Runtime, rec: RequestRecord, server: str, spec: McpServerSpec, msg_id: Any, params: dict[str, Any]
) -> McpResponse:
    policy, identity = rec.policy, rec.identity
    assert identity is not None and rec.profile is not None
    ctx = RequestContext(request_id=rec.request_id, session_id=rec.session_id, endpoint="mcp",
                         stage=Stage.ingress, identity=identity.id, role=identity.role, profile=rec.profile,
                         model=None, segments=[], policy_version=policy.version)
    try:
        stop_if_blocked(rec.add_stage(await run_stage(policy, ctx, Stage.ingress, rt.controls)), rec)
        upstream_params = {"cursor": params["cursor"]} if params.get("cursor") else {}
        res = await rt.upstream.mcp.request(server, spec, rt.env, rec.session_id, "tools/list", upstream_params)
    except GatewayError as exc:
        body = rec.fail(exc).body["error"]
        return McpResponse(200, _error(msg_id, POLICY_ERROR, body["message"], {"aicl": body}),
                           _response_headers(rec, None))
    except UpstreamError as exc:
        rec.fail(GatewayError(ErrorType.upstream_error, str(exc)))
        return McpResponse(200, _upstream_error(msg_id, exc), _response_headers(rec, None))
    rec.upstream_called, rec.upstream_ms = True, res.latency_ms

    shown, hidden = [], []
    for tool in res.result.get("tools") or []:
        name = tool.get("name") if isinstance(tool, dict) else None
        if not isinstance(name, str):
            continue
        gname = f"{server}.{name}"
        tspec: ToolSpec | None = policy.raw.tools.get(gname)
        if tspec is None or tspec.mcp_server != server:
            hidden.append({"tool": name, "reason": f"not declared in the policy as {gname!r}"})
            continue
        if not policy.role_allows_tool(identity.role, gname):
            hidden.append({"tool": name, "reason": f"not permitted for role {identity.role!r}"})
            continue
        # tool poisoning: the description text reaches the agent's model as instructions
        leaves = description_leaves(tool, [])
        segments = [build_segment(i, text, Origin.tool_result, "trusted", {"tool": gname, "data_path": path})
                    for i, (path, text) in enumerate(leaves)]
        if segments:
            scan_ctx = ctx.model_copy(update={"stage": Stage.input, "segments": segments, "tool": gname})
            result = rec.add_stage(await run_stage(policy, scan_ctx, Stage.input, rt.controls))
            if result.stopped:
                d = result.blocking
                hidden.append({"tool": name, "reason": f"description flagged by {d.control_id if d else 'policy'}"})
                continue
            if result.action == Action.redact:
                tool = json.loads(json.dumps(tool))
                for seg in result.segments:
                    if seg.text != segments[seg.idx].text:
                        _set_path(tool, seg.meta["data_path"], seg.text)
        shown.append(tool)

    rec.notes["mcp"]["hidden"] = hidden
    final = rec.final_action()
    rec.emit(final)
    result: dict[str, Any] = {"tools": shown}
    if res.result.get("nextCursor"):
        result["nextCursor"] = res.result["nextCursor"]
    return McpResponse(200, _result(msg_id, result), _response_headers(rec, final))


async def _tools_call(
    rt: Runtime, rec: RequestRecord, server: str, msg_id: Any, params: dict[str, Any], headers: Mapping[str, str]
) -> McpResponse:
    name, args = params.get("name"), params.get("arguments")
    if not isinstance(name, str) or not name:
        return McpResponse(200, _error(msg_id, INVALID_PARAMS, "tools/call needs a tool name"))
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return McpResponse(200, _error(msg_id, INVALID_PARAMS, "tools/call arguments must be an object"))
    gname = f"{server}.{name}"
    rec.notes["mcp"]["tool"] = name

    async def forward(tool_spec: ToolSpec, call_args: dict[str, Any]) -> UpstreamResponse:
        if tool_spec.mcp_server != server:
            raise UpstreamError(f"tool {gname!r} is not served by MCP server {server!r}")
        return await forward_tool(rt, rec, gname, tool_spec, call_args, headers)

    try:
        body = await govern_tool_call(rt, rec, gname, args, forward)
    except GatewayError as exc:
        error = rec.fail(exc).body["error"]
        if exc.type in _POLICY_STOPS:
            return McpResponse(200, _result(msg_id, _stopped_tool_result(error)),
                               _response_headers(rec, Action.require_approval
                                                 if exc.type == ErrorType.approval_required else Action.block))
        cause = exc.__cause__
        if isinstance(cause, UpstreamError):
            return McpResponse(200, _upstream_error(msg_id, cause), _response_headers(rec, None))
        return McpResponse(200, _error(msg_id, INVALID_PARAMS, exc.message, {"aicl": error}),
                           _response_headers(rec, None))
    final = rec.final_action()
    rec.emit(final)
    return McpResponse(200, _result(msg_id, body), _response_headers(rec, final))


def _upstream_error(msg_id: Any, exc: UpstreamError) -> dict[str, Any]:
    if isinstance(exc, McpUpstreamError):  # the upstream's own JSON-RPC error, passed on
        return _error(msg_id, exc.code, exc.message, exc.data)
    return _error(msg_id, INTERNAL_ERROR, str(exc))


def _set_path(root: Any, path: list[Any], value: Any) -> None:
    node = root
    for p in path[:-1]:
        node = node[p]
    node[path[-1]] = value


def handle_mcp_delete(rt: Runtime, server: str, headers: Mapping[str, str]) -> McpResponse:
    """DELETE /mcp/{server}: the client ends its session; the upstream one is dropped too."""
    rec = RequestRecord(rt=rt, endpoint="mcp", headers=headers)
    try:
        rec.authenticate()
    except GatewayError as exc:
        body = rec.fail(exc).body["error"]
        return McpResponse(401, _error(None, AUTH_ERROR, body["message"], {"aicl": body}))
    session = headers.get("mcp-session-id")
    if not session:
        return McpResponse(400, _error(None, INVALID_REQUEST, "Mcp-Session-Id header required"))
    rec.use_session(session)
    rt.upstream.mcp.forget(server, rec.session_id)
    return McpResponse(204, None)

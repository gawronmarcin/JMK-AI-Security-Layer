"""The gateway as an MCP client of upstream MCP servers (Streamable HTTP transport, JSON-RPC 2.0).

    McpClient(upstream).request(server, url, key, "tools/list", {})  -> result dict

* One upstream session per (server, gateway session): initialized on first use (`initialize`
  + `notifications/initialized`), its `Mcp-Session-Id` kept and sent back; an upstream that
  forgets it (HTTP 404) gets a fresh session and the call is retried once.
* Responses may be plain JSON or an SSE stream (`text/event-stream`): the JSON-RPC response
  with the request's id is taken from the stream, other messages (server notifications or
  requests) are ignored - the gateway offers the upstream no sampling/roots/elicitation.
* A JSON-RPC error from the upstream raises McpUpstreamError carrying its code and message;
  transport failures raise UpstreamError (the flow answers -32603).
"""

from __future__ import annotations

import asyncio
import itertools
import json
import time
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from aicl.proxy.upstream import UpstreamError

if TYPE_CHECKING:
    from aicl.policy.schema import McpServerSpec
    from aicl.proxy.upstream import UpstreamClient

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26")
CLIENT_INFO = {"name": "aicl-gateway", "version": "0.2.0"}
MAX_SESSIONS = 5000  # upstream sessions kept (LRU); a dropped one is simply re-initialized


class McpUpstreamError(UpstreamError):
    """The upstream MCP server answered with a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(f"upstream MCP error {code}: {message}")
        self.code, self.message, self.data = code, message, data


class _SessionExpired(Exception):
    pass


@dataclass
class McpResult:
    result: dict[str, Any]
    latency_ms: float


def parse_sse(text: str) -> list[Any]:
    """JSON payloads of the `data:` fields of an SSE stream (one per event)."""
    out, data = [], []
    for line in text.splitlines() + [""]:
        if not line:
            if data:
                try:
                    out.append(json.loads("\n".join(data)))
                except ValueError:
                    pass
                data = []
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
    return out


class McpClient:
    def __init__(self, upstream: UpstreamClient):
        self._upstream = upstream
        self._ids = itertools.count(1)
        self._sessions: OrderedDict[tuple[str, str], str | None] = OrderedDict()
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    def forget(self, server: str, key: str) -> None:
        self._sessions.pop((server, key), None)

    async def request(
        self, server: str, spec: McpServerSpec, env: Mapping[str, str], key: str,
        method: str, params: dict[str, Any] | None = None,
    ) -> McpResult:
        """Send one request on the (server, key) upstream session; returns the JSON-RPC result."""
        url = env.get(spec.url_env)
        if not url:
            raise UpstreamError(f"MCP server {server!r} not configured ({spec.url_env} unset)")
        headers = {}
        if spec.bearer_token_env and env.get(spec.bearer_token_env):
            headers["Authorization"] = f"Bearer {env[spec.bearer_token_env]}"
        start = time.perf_counter()
        for attempt in (1, 2):
            session = await self._session(server, spec, url, headers, key)
            try:
                result = await self._rpc(url, spec, headers, session, method, params or {})
                return McpResult(result, (time.perf_counter() - start) * 1000)
            except _SessionExpired:
                self.forget(server, key)
                if attempt == 2:
                    raise UpstreamError(f"MCP server {server!r} keeps rejecting the session") from None
        raise AssertionError("unreachable")

    async def _session(
        self, server: str, spec: McpServerSpec, url: str, headers: dict[str, str], key: str
    ) -> str | None:
        k = (server, key)
        if k in self._sessions:
            self._sessions.move_to_end(k)
            return self._sessions[k]
        lock = self._locks.setdefault(k, asyncio.Lock())
        async with lock:
            if k in self._sessions:
                return self._sessions[k]
            init = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO}
            msg = {"jsonrpc": "2.0", "id": next(self._ids), "method": "initialize", "params": init}
            resp = await self._post(url, spec, headers, None, msg)
            session = resp.headers.get("mcp-session-id")
            self._read_result(resp, msg["id"])
            note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            await self._post(url, spec, headers, session, note)
            self._sessions[k] = session
            while len(self._sessions) > MAX_SESSIONS:
                old, _ = self._sessions.popitem(last=False)
                self._locks.pop(old, None)
            return session

    async def _rpc(
        self, url: str, spec: McpServerSpec, headers: dict[str, str], session: str | None,
        method: str, params: dict[str, Any],
    ) -> dict[str, Any]:
        msg = {"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params}
        resp = await self._post(url, spec, headers, session, msg)
        if resp.status_code == 404 and session is not None:
            raise _SessionExpired
        return self._read_result(resp, msg["id"])

    async def _post(
        self, url: str, spec: McpServerSpec, headers: dict[str, str], session: str | None, msg: dict[str, Any]
    ) -> httpx.Response:
        h = {**headers, "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL_VERSION}
        if session:
            h["Mcp-Session-Id"] = session
        try:
            return await self._upstream.tool_http().post(url, json=msg, headers=h, timeout=spec.timeout_s)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"MCP server request failed: {type(exc).__name__}") from exc

    def _read_result(self, resp: httpx.Response, msg_id: int) -> dict[str, Any]:
        if resp.status_code >= 400:
            raise UpstreamError(f"MCP server returned HTTP {resp.status_code}")
        ctype = resp.headers.get("content-type", "")
        try:
            messages = parse_sse(resp.text) if "text/event-stream" in ctype else [resp.json()]
        except ValueError as exc:
            raise UpstreamError("MCP server returned invalid JSON") from exc
        for m in messages:
            if isinstance(m, dict) and m.get("id") == msg_id and ("result" in m or "error" in m):
                if "error" in m:
                    err = m["error"] if isinstance(m["error"], dict) else {}
                    raise McpUpstreamError(int(err.get("code", -32603)), str(err.get("message", "error")),
                                           err.get("data"))
                result = m["result"]
                if not isinstance(result, dict):
                    raise UpstreamError("MCP server result is not an object")
                return result
        raise UpstreamError("MCP server sent no response to the request")

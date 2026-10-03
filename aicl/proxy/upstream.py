"""Upstream LLM client. Always non-streaming: output must be inspected before it leaves (§2).

Both providers are called through the OpenAI-compatible chat endpoint (Ollama serves one
at /v1/chat/completions). A model's base URL comes from the env var named in the policy;
it may be given with or without the trailing /v1.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from aicl.policy.schema import ModelSpec, ToolSpec

# Client headers passed through to the upstream. Everything else (notably Authorization)
# stays at the gateway.
FORWARDED_HEADERS = ("x-mock-scenario",)

DEFAULT_TIMEOUT_S = 60.0


class UpstreamError(Exception):
    """Upstream unreachable, failed, or answered with something that is not a chat completion."""


@dataclass
class UpstreamResponse:
    body: dict[str, Any]
    latency_ms: float


def chat_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    return f"{base}/chat/completions" if base.endswith("/v1") else f"{base}/v1/chat/completions"


class UpstreamClient:
    def __init__(
        self,
        env: Mapping[str, str],
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        tool_transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.env = env
        self._transport = transport
        self._tool_transport = tool_transport
        self._timeout = timeout_s
        self._client: httpx.AsyncClient | None = None
        self._tool_client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(transport=self._transport, timeout=self._timeout)
        if self._tool_transport is not None:
            self._tool_client = httpx.AsyncClient(transport=self._tool_transport, timeout=self._timeout)

    async def stop(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        if self._tool_client is not None:
            await self._tool_client.aclose()
            self._tool_client = None

    async def chat(
        self, model: ModelSpec, body: dict[str, Any], headers: Mapping[str, str]
    ) -> UpstreamResponse:
        if self._client is None:
            raise RuntimeError("UpstreamClient not started")
        base_url = self.env.get(model.base_url_env)
        if not base_url:
            raise UpstreamError(
                f"upstream for model {model.name!r} not configured ({model.base_url_env} unset)"
            )

        payload = {**body, "model": model.upstream_model or model.name, "stream": False}
        fwd = {k: v for k, v in headers.items() if k.lower() in FORWARDED_HEADERS}
        start = time.perf_counter()
        try:
            resp = await self._client.post(chat_url(base_url), json=payload, headers=fwd)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream request failed: {type(exc).__name__}") from exc
        latency = (time.perf_counter() - start) * 1000

        if resp.status_code >= 400:
            raise UpstreamError(f"upstream returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise UpstreamError("upstream returned invalid JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
            raise UpstreamError("upstream response has no choices")
        return UpstreamResponse(body=data, latency_ms=latency)

    async def invoke_tool(
        self,
        tool_spec: ToolSpec,
        tool_name: str,
        arguments: Any,
        headers: Mapping[str, str],
    ) -> UpstreamResponse:
        if self._client is None:
            raise RuntimeError("UpstreamClient not started")
        backend_url = self.env.get(tool_spec.backend_url_env)
        if not backend_url:
            raise UpstreamError(
                f"backend for tool {tool_name!r} not configured ({tool_spec.backend_url_env} unset)"
            )

        client = self._tool_client if self._tool_client is not None else self._client
        payload = {"tool": tool_name, "arguments": arguments}
        fwd = {k: v for k, v in headers.items() if k.lower() in FORWARDED_HEADERS}
        start = time.perf_counter()
        try:
            resp = await client.post(backend_url, json=payload, headers=fwd)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"tool backend request failed: {type(exc).__name__}") from exc
        latency = (time.perf_counter() - start) * 1000

        if resp.status_code >= 400:
            raise UpstreamError(f"tool backend returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except ValueError:
            data = {"output": resp.text}
        if not isinstance(data, dict):
            data = {"output": data}
        return UpstreamResponse(body=data, latency_ms=latency)

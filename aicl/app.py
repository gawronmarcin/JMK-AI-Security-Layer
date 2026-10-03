"""FastAPI app factory.

    uvicorn aicl.app:app                      # policy from AICL_POLICY, env from the process

Tests build their own instance and plug mock upstreams in memory:

    app = create_app("policies/default.yaml", env={...}, audit_path=tmp / "audit.jsonl",
                     upstream_transport=httpx.ASGITransport(mock_llm_app))
    async with app.router.lifespan_context(app):   # starts audit writer + HTTP client
        ...

`app.state.runtime` gives tests access to the audit writer, state store and policy.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from aicl import feeds, registry
from aicl.audit import AuditWriter
from aicl.flows.chat import handle_chat
from aicl.flows.common import BodyReader, BodyTooLarge, FlowResponse
from aicl.models import Control
from aicl.policy.loader import load_policy_file
from aicl.proxy import UpstreamClient
from aicl.runtime import Runtime
from aicl.state import InMemoryStore

DEFAULT_POLICY = "policies/default.yaml"


def create_app(
    policy_path: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    base_dir: str | Path | None = None,
    audit_path: str | Path | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    controls: Mapping[str, Control] | None = None,
) -> FastAPI:
    """Build the gateway. Raises PolicyError if the policy is invalid (fail fast at startup).

    env:                identity keys and upstream URLs; defaults to os.environ
    base_dir:           relative paths (audit, feeds) resolve against it; defaults to cwd
    upstream_transport: httpx transport for LLM upstreams (tests: ASGITransport of a mock)
    controls:           control set to run; defaults to every registered control
    """
    env = os.environ if env is None else env
    base = Path.cwd() if base_dir is None else Path(base_dir)
    policy_path = Path(policy_path or env.get("AICL_POLICY") or DEFAULT_POLICY)
    policy = load_policy_file(policy_path if policy_path.is_absolute() else base / policy_path, env)

    if controls is None:
        registry.discover()
    audit_file = Path(audit_path) if audit_path is not None else base / policy.raw.audit.path
    feeds.store.base_dir = base

    rt = Runtime(
        policy=policy,
        env=env,
        state=InMemoryStore(),
        audit=AuditWriter(audit_file, policy.raw.audit.max_event_bytes),
        upstream=UpstreamClient(env, transport=upstream_transport),
        feeds=feeds.store,
        controls=controls,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await rt.start()
        try:
            yield
        finally:
            await rt.stop()

    app = FastAPI(title="AI Control Layer", lifespan=lifespan)
    app.state.runtime = rt

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "policy_version": rt.policy.version,
            "feed_version": rt.feeds.current().version,
        }

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        flow = await handle_chat(rt, _body_reader(request), _headers(request))
        return _respond(flow)

    return app


def _body_reader(request: Request) -> BodyReader:
    """Reads the body only when the flow asks, stopping as soon as it exceeds the limit."""

    async def read(limit: int | None) -> bytes:
        if limit is not None:
            declared = request.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > limit:
                raise BodyTooLarge(int(declared))
        buf = bytearray()
        async for chunk in request.stream():
            buf += chunk
            if limit is not None and len(buf) > limit:
                raise BodyTooLarge(len(buf))
        return bytes(buf)

    return read


def _headers(request: Request) -> dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


def _respond(flow: FlowResponse) -> Response:
    if flow.stream and flow.status == 200:
        return StreamingResponse(_sse(flow.body), media_type="text/event-stream", headers=flow.headers)
    return JSONResponse(flow.body, status_code=flow.status, headers=flow.headers)


async def _sse(body: dict[str, Any]) -> AsyncIterator[str]:
    """Pseudo-streaming: re-emit an already checked completion as OpenAI-style SSE chunks."""
    base = {k: body[k] for k in ("id", "created", "model") if k in body} | {"object": "chat.completion.chunk"}
    for choice in body.get("choices", []):
        message = choice.get("message") or {}
        delta = {k: message[k] for k in ("role", "content", "tool_calls") if message.get(k) is not None}
        index = choice.get("index", 0)
        yield _chunk(base | {"choices": [{"index": index, "delta": delta, "finish_reason": None}]})
        yield _chunk(
            base
            | {
                "choices": [
                    {"index": index, "delta": {}, "finish_reason": choice.get("finish_reason", "stop")}
                ]
            }
        )
    yield "data: [DONE]\n\n"


def _chunk(data: dict[str, Any]) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def __getattr__(name: str) -> Any:
    # `uvicorn aicl.app:app` builds the app lazily, so importing this module has no side effects.
    if name == "app":
        return create_app()
    raise AttributeError(name)

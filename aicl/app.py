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
import mimetypes
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from aicl import feeds, registry
from aicl.admin import policy as admin_policy
from aicl.admin import telemetry as admin_telemetry
from aicl.audit import AuditWriter
from aicl.flows.artifact_scan import handle_artifact_scan
from aicl.flows.chat import handle_chat
from aicl.flows.common import BodyReader, BodyTooLarge, FlowResponse
from aicl.flows.tool_invoke import handle_tool_invoke
from aicl.integrations import classifier_listener, detector_status, semantic_judge_listener
from aicl.models import Control
from aicl.policy.loader import load_policy_file
from aicl.proxy import UpstreamClient
from aicl.runtime import Runtime
from aicl.state import InMemoryStore

DEFAULT_POLICY = "policies/default.yaml"
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"

# The dashboard loads ES modules, which browsers refuse unless served as JavaScript. On Windows
# Python may take the .js type from the registry (often text/plain), so set it explicitly.
mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/javascript", ".mjs")


def create_app(
    policy_path: str | Path | None = None,
    *,
    env: Mapping[str, str] | None = None,
    base_dir: str | Path | None = None,
    audit_path: str | Path | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
    tool_transport: httpx.AsyncBaseTransport | None = None,
    controls: Mapping[str, Control] | None = None,
    reload_interval: float | None = 1.0,
) -> FastAPI:
    """Build the gateway. Raises PolicyError if the policy is invalid (fail fast at startup).

    env:                identity keys and upstream URLs; defaults to os.environ
    base_dir:           relative paths (audit, feeds) resolve against it; defaults to cwd
    upstream_transport: httpx transport for LLM upstreams (tests: ASGITransport of a mock)
    tool_transport:     httpx transport for tool backends (defaults to upstream_transport if unset)
    controls:           control set to run; defaults to every registered control
    reload_interval:    seconds between policy/feed file checks; None disables hot reload
                        (`app.state.runtime.reload_policy()` still works)
    """
    env = os.environ if env is None else env
    base = Path.cwd() if base_dir is None else Path(base_dir)
    policy_path = Path(policy_path or env.get("AICL_POLICY") or DEFAULT_POLICY)
    if not policy_path.is_absolute():
        policy_path = base / policy_path
    policy = load_policy_file(policy_path, env)

    if controls is None:
        registry.discover()
    audit_file = Path(audit_path) if audit_path is not None else base / policy.raw.audit.path
    feeds.store.base_dir = base

    from aicl.state import set_store

    rt = Runtime(
        policy=policy,
        env=env,
        state=InMemoryStore(),
        audit=AuditWriter(audit_file, policy.raw.audit.max_event_bytes),
        upstream=UpstreamClient(env, transport=upstream_transport, tool_transport=tool_transport),
        feeds=feeds.store,
        controls=controls,
        policy_path=policy_path,
        reload_interval=reload_interval,
        policy_listeners=[semantic_judge_listener(env), classifier_listener(env)],
    )
    set_store(rt.state)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await rt.start()
        try:
            yield
        finally:
            await rt.stop()

    app = FastAPI(title="AI Control Layer", lifespan=lifespan)
    app.state.runtime = rt

    app.include_router(admin_policy.router(rt))
    app.include_router(admin_telemetry.router(rt))

    @app.get("/healthz")
    @app.get("/livez")
    @app.get("/readyz")
    async def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "policy_version": rt.policy.version,
            "feed_version": rt.feeds.current().version,
            "detectors": detector_status(),
        }

    # Static dashboard (aicl/dashboard/README.md). It only calls /healthz and /admin/*, with the
    # admin key the operator types in; the files themselves are public and contain no data.
    @app.get("/dashboard", include_in_schema=False)
    async def dashboard_redirect() -> Response:
        return RedirectResponse("/dashboard/")

    app.mount("/dashboard", _RevalidatedStaticFiles(directory=DASHBOARD_DIR, html=True), name="dashboard")

    @app.post("/v1/chat/completions")
    @app.post("/v1/chat")
    async def chat_completions(request: Request) -> Response:
        flow = await handle_chat(rt, _body_reader(request), _headers(request))
        return _respond(flow)

    @app.post("/v1/tools/invoke")
    async def tools_invoke(request: Request) -> Response:
        flow = await handle_tool_invoke(rt, _body_reader(request), _headers(request))
        return _respond(flow)

    @app.post("/v1/artifacts/scan")
    async def artifacts_scan(request: Request) -> Response:
        flow = await handle_artifact_scan(rt, request, _body_reader(request), _headers(request))
        return _respond(flow)

    return app


class _RevalidatedStaticFiles(StaticFiles):
    """Dashboard files with `Cache-Control: no-cache`: browsers revalidate (cheap, ETag) instead of
    running stale JS modules after an update."""

    def file_response(self, *args: Any, **kwargs: Any) -> Response:
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


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

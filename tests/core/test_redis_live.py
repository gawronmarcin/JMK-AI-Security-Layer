"""Shared state on a REAL Redis (the other state tests use an in-memory fake without Lua).

Skipped unless AICL_TEST_REDIS_URL is set; the database in the URL is flushed, so use a spare one:

    docker run -d -p 6379:6379 redis:7-alpine        # or: podman run ...
    pip install -e ".[redis]"
    AICL_TEST_REDIS_URL=redis://localhost:6379/15 pytest tests/core/test_redis_live.py
"""

from __future__ import annotations

import asyncio
import os
from contextlib import AsyncExitStack, asynccontextmanager

import httpx
import pytest
from fake_tools import make_mock_tools
from fake_upstream import make_fake_upstream
from policy_files import write_policy

from aicl.app import create_app
from aicl.state.redis_store import RedisStore

URL = os.environ.get("AICL_TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(not URL, reason="needs a real Redis: AICL_TEST_REDIS_URL=redis://host:6379/<spare db>")

KEYS = {"support": "k-support", "research": "k-research", "admin": "k-admin"}
ENV = {
    "AICL_KEY_SUPPORT": KEYS["support"],
    "AICL_KEY_RESEARCH": KEYS["research"],
    "AICL_KEY_ADMIN": KEYS["admin"],
    "AICL_UPSTREAM_MOCK_URL": "http://mock-llm",
    "AICL_TOOL_DOCS_URL": "http://mock-tools/search_docs",
    "AICL_TOOL_FETCH_URL": "http://mock-tools/fetch_url",
    "AICL_TOOL_MAIL_URL": "http://mock-tools/send_email",
    "AICL_TOOL_SHELL_URL": "http://mock-tools/run_shell",
    "AICL_STATE_URL": URL or "",
}
OVERLAY = {
    "taint": {"enabled": True, "blocked_privileges_when_tainted": ["high", "critical"],
              "action": "require_approval", "session_ttl_seconds": 3600},
    "budgets": {"support_default": {"max_requests_per_minute": 20}},
}
EMAIL = {"tool": "send_email", "arguments": {"to": "ops@example.com", "subject": "Update", "body": "All good"}}
CHAT = {"model": "mock-commercial", "messages": [{"role": "user", "content": "hi"}]}


@pytest.fixture(autouse=True)
def _flush():
    import redis

    redis.Redis.from_url(URL).flushdb()
    yield


def _auth(who, approval_id=None, session=None):
    h = {"Authorization": f"Bearer {KEYS[who]}"}
    if approval_id:
        h["X-AICL-Approval-Id"] = approval_id
    if session:
        h["X-AICL-Session"] = session
    return h


@asynccontextmanager
async def _two_gateways(tmp_path):
    async with AsyncExitStack() as stack:
        clients = []
        for name in ("a", "b"):
            (tmp_path / name).mkdir()
            app = create_app(write_policy(tmp_path / name, OVERLAY), env=ENV, audit_path=tmp_path / name / "audit.jsonl",
                             upstream_transport=httpx.ASGITransport(make_fake_upstream()[0]),
                             tool_transport=httpx.ASGITransport(make_mock_tools()[0]))
            await stack.enter_async_context(app.router.lifespan_context(app))
            clients.append(await stack.enter_async_context(
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")))
            assert isinstance(app.state.runtime.state, RedisStore)
        yield clients


async def test_rate_limit_holds_exactly_across_two_instances(tmp_path):
    async with _two_gateways(tmp_path) as (a, b):
        calls = [(a if i % 2 else b).post("/v1/chat/completions", json=CHAT, headers=_auth("support"))
                 for i in range(60)]
        codes = [r.status_code for r in await asyncio.gather(*calls)]
        assert codes.count(200) == 20 and codes.count(429) == 40


async def test_taint_and_approval_are_shared_across_instances(tmp_path):
    async with _two_gateways(tmp_path) as (a, b):
        # untrusted tool output on instance A taints the session ...
        r = await a.post("/v1/tools/invoke", json={"tool": "search_docs", "arguments": {"query": "x"}},
                         headers=_auth("support", session="s-shared"))
        assert r.status_code == 200
        # ... so a privileged call on instance B needs an operator
        r = await b.post("/v1/tools/invoke", json=EMAIL, headers=_auth("support", session="s-shared"))
        assert r.status_code == 403 and r.json()["error"]["type"] == "aicl_approval_required"
        approval_id = r.json()["error"]["approval_id"]
        assert (await a.post(f"/admin/approvals/{approval_id}/approve", headers=_auth("admin"))).status_code == 200
        ok = await b.post("/v1/tools/invoke", json=EMAIL, headers=_auth("support", approval_id, "s-shared"))
        assert ok.status_code == 200
        again = await a.post("/v1/tools/invoke", json=EMAIL, headers=_auth("support", approval_id, "s-shared"))
        assert again.status_code == 403 and "already used" in again.json()["error"]["message"]


async def test_budget_lock_release_is_compare_and_delete():
    store = RedisStore.from_url(URL)
    token = await store._acquire_lock("alice")
    lock_key = store._k("lock", "budget", "alice")
    await store.r.set(lock_key, "someone-else")  # ours expired and another instance took it
    await store._release_lock("alice", token)  # Lua path on a real server
    assert (await store.r.get(lock_key)) == b"someone-else"
    await store.r.delete(lock_key)
    token = await store._acquire_lock("alice")
    await store._release_lock("alice", token)
    assert await store.r.get(lock_key) is None

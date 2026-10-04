"""Shared state for several gateway instances (AICL_STATE_URL): HITL approvals in Redis, and two
gateway apps sharing one (fake) Redis for approvals and budgets."""

from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from datetime import UTC, datetime

import httpx
import pytest
from fake_redis import Data, FakeAsyncRedis, FakeRedis
from fake_tools import make_mock_tools
from fake_upstream import make_fake_upstream
from policy_files import write_policy

from aicl.app import create_app
from aicl.approvals import ApprovalStore, RedisApprovalStore
from aicl.state.redis_store import RedisStore

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
}


def _create(store, identity="agent", fingerprint="f1"):
    return store.create(request_id="r", session_id="s", control_id="C-TAINT", threat_ids=["TH-19"],
                        reason="tainted", identity=identity, fingerprint=fingerprint, summary="send_email(...)")


@pytest.fixture(params=["memory", "redis"])
def store(request):
    return ApprovalStore() if request.param == "memory" else RedisApprovalStore(FakeRedis())


def test_pending_request_is_reused(store):
    a = _create(store)
    assert store.find_pending("agent", "f1").approval_id == a.approval_id
    assert store.find_pending("other", "f1") is None


def test_single_use_and_binding(store):
    a = _create(store)
    store.approve(a.approval_id, decided_by="alice")
    assert store.consume(a.approval_id, identity="mallory", fingerprint="f1", request_id="x") == (
        False, "approval belongs to another identity")
    assert store.consume(a.approval_id, identity="agent", fingerprint="f2", request_id="x") == (
        False, "approval was granted for a different action")
    assert store.consume(a.approval_id, identity="agent", fingerprint="f1", request_id="x")[0]
    assert store.consume(a.approval_id, identity="agent", fingerprint="f1", request_id="y") == (
        False, "approval already used")
    assert store.get(a.approval_id).used_by_request == "x"


def test_decision_is_final_and_expires(store):
    store.ttl_seconds = 0
    a = _create(store)
    assert store.approve(a.approval_id, "alice").status == "approved"
    assert store.reject(a.approval_id, "bob").status == "approved"  # first decision wins
    assert datetime.fromisoformat(store.get(a.approval_id).expires_at) <= datetime.now(UTC)
    assert store.consume(a.approval_id, identity="agent", fingerprint="f1", request_id="x") == (
        False, "approval expired")


def test_two_instances_share_approvals():
    data = Data()
    a, b = RedisApprovalStore(FakeRedis(data)), RedisApprovalStore(FakeRedis(data))
    req = _create(a)
    assert _create(b).approval_id == req.approval_id  # same action on another instance: same request
    a.approve(req.approval_id, "alice")
    assert b.reject(req.approval_id, "bob").status == "approved"
    assert b.consume(req.approval_id, identity="agent", fingerprint="f1", request_id="x")[0]
    assert a.consume(req.approval_id, identity="agent", fingerprint="f1", request_id="y") == (
        False, "approval already used")
    assert [i.approval_id for i in a.list()] == [req.approval_id]


# --------------------------------------------------------------------------- two gateway instances

TAINT_APPROVAL = {"taint": {"enabled": True, "blocked_privileges_when_tainted": ["high", "critical"],
                            "action": "require_approval", "session_ttl_seconds": 3600}}
EMAIL = {"tool": "send_email", "session_id": "s-shared",
         "arguments": {"to": "ops@example.com", "subject": "Update", "body": "All good"}}


@asynccontextmanager
async def _two_gateways(tmp_path, monkeypatch):
    data = Data()
    monkeypatch.setattr(RedisStore, "from_url", classmethod(lambda cls, url, **kw: cls(FakeAsyncRedis(data), **kw)))
    monkeypatch.setattr(RedisApprovalStore, "from_url",
                        classmethod(lambda cls, url, **kw: cls(FakeRedis(data), **kw)))
    env = {**ENV, "AICL_STATE_URL": "redis://fake:6379/0"}
    async with AsyncExitStack() as stack:
        clients = []
        for name in ("a", "b"):
            app = create_app(write_policy(tmp_path / name, TAINT_APPROVAL), env=env,
                             upstream_transport=httpx.ASGITransport(make_fake_upstream()[0]),
                             tool_transport=httpx.ASGITransport(make_mock_tools()[0]))
            await stack.enter_async_context(app.router.lifespan_context(app))
            client = await stack.enter_async_context(
                httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test"))
            clients.append((app, client))
        yield clients, data


def _auth(who, approval_id=None):
    h = {"Authorization": f"Bearer {KEYS[who]}"}
    if approval_id:
        h["X-AICL-Approval-Id"] = approval_id
    return h


async def test_approval_flow_across_two_gateway_instances(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    async with _two_gateways(tmp_path, monkeypatch) as (((app_a, a), (app_b, b)), _):
        assert isinstance(app_a.state.runtime.state, RedisStore)
        await app_a.state.runtime.state.mark_tainted("s-shared", "untrusted_input")  # taint seen by both
        r = await b.post("/v1/tools/invoke", json=EMAIL, headers=_auth("support"))
        assert r.status_code == 403
        approval_id = r.json()["error"]["approval_id"]
        assert (await a.post(f"/admin/approvals/{approval_id}/approve", headers=_auth("admin"))).status_code == 200
        ok = await b.post("/v1/tools/invoke", json=EMAIL, headers=_auth("support", approval_id))
        assert ok.status_code == 200
        again = await a.post("/v1/tools/invoke", json=EMAIL, headers=_auth("support", approval_id))
        assert again.status_code == 403 and "already used" in again.json()["error"]["message"]


async def test_budgets_add_up_across_instances(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    async with _two_gateways(tmp_path, monkeypatch) as (((app_a, a), (_, b)), _):
        body = {"model": "mock-commercial", "messages": [{"role": "user", "content": "hi"}]}
        for client in (a, b, a):
            assert (await client.post("/v1/chat/completions", json=body, headers=_auth("support"))).status_code == 200
        usage = await app_a.state.runtime.state.get_usage("support-agent-01", "minute")
        assert usage.requests == 3


def test_state_url_without_redis_package_fails_fast(tmp_path):
    pytest.importorskip("aicl")
    try:
        import redis  # noqa: F401
    except ImportError:
        with pytest.raises(RuntimeError, match=r"pip install -e \".\[redis\]\""):
            create_app(write_policy(tmp_path), env={**ENV, "AICL_STATE_URL": "redis://localhost:6379/0"})
    else:
        pytest.skip("redis package installed: the missing-package path cannot be exercised")

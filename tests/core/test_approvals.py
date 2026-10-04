"""Tests for Human-in-the-Loop (HITL) approval store, admin endpoints, and gateway integration."""

from __future__ import annotations

import httpx
import pytest
from fake_tools import make_mock_tools
from fake_upstream import make_fake_upstream
from policy_files import write_policy

from aicl.app import create_app
from aicl.approvals import ApprovalStore

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


def test_approval_store_crud():
    store = ApprovalStore()
    appr = store.create(
        request_id="req_123",
        session_id="sess_abc",
        control_id="C-TAINT",
        threat_ids=["TH-19"],
        reason="high privilege in tainted session",
        identity="support-agent-01",
        action_type="tool_invoke",
    )
    assert appr.approval_id.startswith("appr_")
    assert appr.status == "pending"

    # get
    assert store.get(appr.approval_id) == appr
    assert store.get("nonexistent") is None

    # list
    assert len(store.list()) == 1
    assert len(store.list(status="pending")) == 1
    assert len(store.list(status="approved")) == 0

    # approve
    approved = store.approve(appr.approval_id, decided_by="admin_alice")
    assert approved is not None
    assert approved.status == "approved"
    assert approved.decided_by == "admin_alice"
    assert store.is_approved(appr.approval_id) is True

    # reject
    appr2 = store.create(
        request_id="req_456",
        session_id="sess_def",
        control_id="C-CODE-EXEC",
        threat_ids=["TH-15"],
        reason="executing arbitrary code",
    )
    rejected = store.reject(appr2.approval_id, decided_by="admin_bob")
    assert rejected is not None
    assert rejected.status == "rejected"
    assert store.is_approved(appr2.approval_id) is False


@pytest.mark.asyncio
async def test_admin_approvals_api_endpoints(tmp_path):
    policy_path = write_policy(tmp_path)
    llm_mock, _ = make_fake_upstream()
    tools_mock, _ = make_mock_tools()
    app = create_app(
        policy_path,
        env=ENV,
        upstream_transport=httpx.ASGITransport(llm_mock),
        tool_transport=httpx.ASGITransport(tools_mock),
    )

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        rt = app.state.runtime
        appr = rt.approvals.create(
            request_id="req_test",
            session_id="sess_test",
            control_id="C-TAINT",
            threat_ids=["TH-19"],
            reason="tainted session approval required",
        )

        # Unauthorized access to admin endpoint
        r = await client.get("/admin/approvals")
        assert r.status_code == 401

        # Non-admin access
        r = await client.get(
            "/admin/approvals",
            headers={"Authorization": f"Bearer {KEYS['support']}"},
        )
        assert r.status_code == 403

        # Admin access - list
        r = await client.get(
            "/admin/approvals",
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["approvals"][0]["approval_id"] == appr.approval_id

        # Get approval details
        r = await client.get(
            f"/admin/approvals/{appr.approval_id}",
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 200
        assert r.json()["approval_id"] == appr.approval_id

        # Approve
        r = await client.post(
            f"/admin/approvals/{appr.approval_id}/approve",
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "approved"
        assert rt.approvals.is_approved(appr.approval_id) is True

        # Non-existent approval
        r = await client.get(
            "/admin/approvals/appr_nonexistent",
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 404


@pytest.mark.asyncio
async def test_gateway_hitl_approval_flow(tmp_path):
    policy_overlay = {
        "taint": {
            "enabled": True,
            "blocked_privileges_when_tainted": ["high", "critical"],
            "action": "require_approval",
            "session_ttl_seconds": 3600,
        }
    }
    policy_path = write_policy(tmp_path, policy_overlay)
    llm_mock, _ = make_fake_upstream()
    tools_mock, _ = make_mock_tools()
    app = create_app(
        policy_path,
        env=ENV,
        upstream_transport=httpx.ASGITransport(llm_mock),
        tool_transport=httpx.ASGITransport(tools_mock),
    )

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        headers = {"Authorization": f"Bearer {KEYS['support']}"}
        session_id = "sess_hitl_01"

        # Taint session in runtime
        await app.state.runtime.state.mark_tainted(f"support-agent-01:{session_id}", "untrusted_input")

        invoke_payload = {
            "session_id": session_id,
            "tool": "send_email",
            "arguments": {
                "to": "ops@example.com",
                "subject": "System Update",
                "body": "All systems operational",
            },
        }

        # 1. First invocation -> blocked with require_approval (HTTP 403)
        r = await client.post("/v1/tools/invoke", json=invoke_payload, headers=headers)
        assert r.status_code == 403
        err = r.json()["error"]
        assert err["type"] == "aicl_approval_required"
        assert err["control_id"] == "C-TAINT"
        approval_id = err.get("approval_id")
        assert approval_id is not None
        assert approval_id.startswith("appr_")

        # 2. Retrying without approval still fails
        r2 = await client.post("/v1/tools/invoke", json=invoke_payload, headers=headers)
        assert r2.status_code == 403
        assert r2.json()["error"]["type"] == "aicl_approval_required"

        # 3. Admin approves
        r_appr = await client.post(
            f"/admin/approvals/{approval_id}/approve",
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r_appr.status_code == 200
        assert r_appr.json()["status"] == "approved"

        # 4. Client retries with X-AICL-Approval-Id header -> permitted!
        retry_headers = {**headers, "X-AICL-Approval-Id": approval_id}
        r_ok = await client.post("/v1/tools/invoke", json=invoke_payload, headers=retry_headers)
        assert r_ok.status_code == 200
        assert "Email successfully sent" in r_ok.json().get("output", "")


# --------------------------------------------------------------------------- binding (no replay)

from contextlib import asynccontextmanager  # noqa: E402

TAINT_APPROVAL = {"taint": {"enabled": True, "blocked_privileges_when_tainted": ["high", "critical"],
                            "action": "require_approval", "session_ttl_seconds": 3600}}
EMAIL = {"tool": "send_email", "arguments": {"to": "ops@example.com", "subject": "Update", "body": "All good"}}


@asynccontextmanager
async def _gateway(tmp_path):
    app = create_app(
        write_policy(tmp_path, TAINT_APPROVAL),
        env=ENV,
        upstream_transport=httpx.ASGITransport(make_fake_upstream()[0]),
        tool_transport=httpx.ASGITransport(make_mock_tools()[0]),
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client,
    ):
        yield app, client


def _auth(who: str, approval_id: str | None = None) -> dict[str, str]:
    h = {"Authorization": f"Bearer {KEYS[who]}"}
    if approval_id:
        h["X-AICL-Approval-Id"] = approval_id
    return h


async def _ask_and_approve(app, client, session: str, body: dict = EMAIL) -> str:
    await app.state.runtime.state.mark_tainted(f"support-agent-01:{session}", "untrusted_input")
    r = await client.post("/v1/tools/invoke", json={**body, "session_id": session}, headers=_auth("support"))
    assert r.status_code == 403 and r.json()["error"]["type"] == "aicl_approval_required"
    approval_id = r.json()["error"]["approval_id"]
    r = await client.post(f"/admin/approvals/{approval_id}/approve", headers=_auth("admin"))
    assert r.status_code == 200
    return approval_id


async def test_approval_is_single_use(tmp_path):
    async with _gateway(tmp_path) as (app, client):
        approval_id = await _ask_and_approve(app, client, "s1")
        body = {**EMAIL, "session_id": "s1"}
        ok = await client.post("/v1/tools/invoke", json=body, headers=_auth("support", approval_id))
        assert ok.status_code == 200
        assert ok.headers.get("X-AICL-Action") != "require_approval"  # executed with approval
        again = await client.post("/v1/tools/invoke", json=body, headers=_auth("support", approval_id))
        assert again.status_code == 403
        assert "already used" in again.json()["error"]["message"]


async def test_approval_does_not_cover_other_arguments(tmp_path):
    async with _gateway(tmp_path) as (app, client):
        approval_id = await _ask_and_approve(app, client, "s2")
        other = {"tool": "send_email",
                 "arguments": {"to": "attacker@evil.example", "subject": "Update", "body": "All good"},
                 "session_id": "s2"}
        r = await client.post("/v1/tools/invoke", json=other, headers=_auth("support", approval_id))
        assert r.status_code == 403
        assert "different action" in r.json()["error"]["message"]
        # the approval is still unused: the approved action itself goes through
        ok = await client.post("/v1/tools/invoke", json={**EMAIL, "session_id": "s2"},
                               headers=_auth("support", approval_id))
        assert ok.status_code == 200


async def test_approval_does_not_cover_other_identity(tmp_path):
    async with _gateway(tmp_path) as (app, client):
        approval_id = await _ask_and_approve(app, client, "s3")
        await app.state.runtime.state.mark_tainted("admin:s3-admin", "untrusted_input")
        r = await client.post("/v1/tools/invoke", json={**EMAIL, "session_id": "s3-admin"},
                              headers=_auth("admin", approval_id))
        assert r.status_code == 403
        assert "another identity" in r.json()["error"]["message"]


async def test_expired_approval_is_refused(tmp_path):
    async with _gateway(tmp_path) as (app, client):
        app.state.runtime.approvals.ttl_seconds = 0
        approval_id = await _ask_and_approve(app, client, "s4")
        r = await client.post("/v1/tools/invoke", json={**EMAIL, "session_id": "s4"},
                              headers=_auth("support", approval_id))
        assert r.status_code == 403 and "expired" in r.json()["error"]["message"]


async def test_retries_reuse_the_pending_approval_and_operator_sees_the_action(tmp_path):
    async with _gateway(tmp_path) as (app, client):
        await app.state.runtime.state.mark_tainted("support-agent-01:s5", "untrusted_input")
        body = {**EMAIL, "session_id": "s5"}
        ids = set()
        for _ in range(3):
            r = await client.post("/v1/tools/invoke", json=body, headers=_auth("support"))
            ids.add(r.json()["error"]["approval_id"])
        assert len(ids) == 1  # no queue flooding
        item = (await client.get(f"/admin/approvals/{ids.pop()}", headers=_auth("admin"))).json()
        assert item["summary"].startswith("send_email(") and "ops@example.com" in item["summary"]
        assert item["payload"]["tool"] == "send_email" and item["payload"]["args"]["to"] == "ops@example.com"
        assert len(item["fingerprint"]) == 64


async def test_decision_is_final_and_records_the_admin(tmp_path):
    async with _gateway(tmp_path) as (app, client):
        approval_id = await _ask_and_approve(app, client, "s6")
        item = app.state.runtime.approvals.get(approval_id)
        assert item.decided_by == "admin" and item.expires_at is not None  # admin identity id from the key
        r = await client.post(f"/admin/approvals/{approval_id}/reject", headers=_auth("admin"))
        assert r.status_code == 409
        assert app.state.runtime.approvals.get(approval_id).status == "approved"


async def test_approval_lifecycle_is_audited(tmp_path):
    async with _gateway(tmp_path) as (app, client):
        approval_id = await _ask_and_approve(app, client, "s7")
        await client.post("/v1/tools/invoke", json={**EMAIL, "session_id": "s7"}, headers=_auth("support", approval_id))
        await client.post("/v1/tools/invoke", json={**EMAIL, "session_id": "s7"}, headers=_auth("support", approval_id))
        types = [e.type for e in app.state.runtime.audit.recent_events()]
        for t in ("approval.requested", "approval.decided", "approval.used", "approval.refused"):
            assert t in types, t
        used = next(e for e in app.state.runtime.audit.recent_events()
                    if e.type == "request" and e.detail and e.detail.get("approval"))
        assert used.detail["approval"]["approval_id"] == approval_id
        assert used.final_action is not None and used.final_action.value != "require_approval"

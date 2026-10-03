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
        await app.state.runtime.state.mark_tainted(session_id, "untrusted_input")

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

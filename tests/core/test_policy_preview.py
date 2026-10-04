"""Tests for POST /admin/policy/preview (Policy preview & replay)."""

from __future__ import annotations

import httpx
import pytest
from fake_tools import make_mock_tools
from fake_upstream import make_fake_upstream
from policy_files import write_policy

from aicl.app import create_app
from aicl.audit import new_event
from aicl.models import Action, AuditDecision

KEYS = {"support": "k-support", "admin": "k-admin"}
ENV = {
    "AICL_KEY_SUPPORT": KEYS["support"],
    "AICL_KEY_ADMIN": KEYS["admin"],
    "AICL_UPSTREAM_MOCK_URL": "http://mock-llm",
}


@pytest.mark.asyncio
async def test_admin_policy_preview(tmp_path):
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
        # Pre-seed audit event where a request was allowed
        evt = new_event(
            "request",
            request_id="req_replay_01",
            session_id="sess_replay_01",
            endpoint="chat",
            identity="support-agent-01",
            role="support_agent",
            profile="balanced",
            model="mock-fast",
            final_action=Action.allow,
            decisions=[
                AuditDecision(
                    control_id="C-INJ-PAT",
                    threat_ids=["TH-01"],
                    action=Action.block,
                    reason="prompt injection pattern detected",
                )
            ],
        )
        rt.audit.emit(evt)

        # 1. Non-admin is rejected
        r = await client.post(
            "/admin/policy/preview",
            content=policy_path.read_text(),
            headers={"Authorization": f"Bearer {KEYS['support']}"},
        )
        assert r.status_code == 403

        # 2. Admin calls preview with active policy -> 0 changes
        r = await client.post(
            "/admin/policy/preview",
            content=policy_path.read_text(),
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["total_replayed"] >= 1
        assert "diff" in data

        # 3. Candidate policy modifies model allowlist (removes mock-fast)
        candidate_yaml = policy_path.read_text().replace('name: "mock-fast"', 'name: "other-model"')
        r = await client.post(
            "/admin/policy/preview",
            json={"policy": candidate_yaml, "last_n": 10},
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 200
        diff_data = r.json()
        assert diff_data["changed_count"] >= 1
        diff_entry = next(d for d in diff_data["diff"] if d["request_id"] == "req_replay_01")
        assert diff_entry["original_action"] == "allow"
        assert diff_entry["candidate_action"] == "block"

        # 4. Candidate policy removes identity -> blocked
        cand_no_ident = policy_path.read_text().replace("id: support-agent-01", "id: removed-agent")
        r = await client.post(
            "/admin/policy/preview",
            json={"policy": cand_no_ident, "limit": 10},
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 200
        diff_ident = r.json()
        entry_ident = next(d for d in diff_ident["diff"] if d["request_id"] == "req_replay_01")
        assert entry_ident["candidate_action"] == "block"
        assert any("identity 'support-agent-01' is not defined" in reason for reason in entry_ident["reasons"])

        # 5. Shadow-suppressed event re-evaluated under enforce
        evt_shadow = new_event(
            "request",
            request_id="req_replay_02",
            session_id="sess_replay_02",
            endpoint="chat",
            identity="support-agent-01",
            role="support_agent",
            profile="balanced",
            model="mock-fast",
            final_action=Action.allow,
            decisions=[
                AuditDecision(
                    control_id="C-INJ-PAT",
                    threat_ids=["TH-01"],
                    action=Action.allow,
                    shadow_suppressed=True,
                    reason="prompt injection pattern detected in shadow mode",
                )
            ],
        )
        rt.audit.emit(evt_shadow)

        r = await client.post(
            "/admin/policy/preview",
            content=policy_path.read_text(),
            headers={"Authorization": f"Bearer {KEYS['admin']}"},
        )
        assert r.status_code == 200
        shadow_eval = r.json()
        entry_shadow = next(d for d in shadow_eval["diff"] if d["request_id"] == "req_replay_02")
        assert entry_shadow["original_action"] == "allow"
        assert entry_shadow["candidate_action"] == "block"
        assert any("was shadow-suppressed previously, now enforced" in r for r in entry_shadow["reasons"])

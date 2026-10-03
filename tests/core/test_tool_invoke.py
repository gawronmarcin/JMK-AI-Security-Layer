"""Tests for POST /v1/tools/invoke (§1.2, §5.1, §5.3).

Verifies the tool invocation flow:
  ingress -> tool_call -> backend -> tool_result -> post
"""

from __future__ import annotations

import json
import sys
from contextlib import asynccontextmanager
from pathlib import Path

REPO = Path(__file__).parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import httpx
import pytest
from fake_tools import make_mock_tools
from fake_upstream import make_fake_upstream
from policy_files import write_policy

from aicl.app import create_app
from aicl.audit import iter_events
from aicl.models import Action

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


class ToolGateway:
    def __init__(self, app, client, tool_calls, audit_path):
        self.app = app
        self.client = client
        self.tool_calls = tool_calls
        self.audit_path = audit_path

    async def invoke(
        self,
        tool: str,
        arguments: dict | None = None,
        *,
        key: str = "support",
        session_id: str | None = None,
        caller_agent: str | None = None,
        scenario: str | None = None,
        headers: dict | None = None,
        raw_body: dict | None = None,
    ):
        h = {"Authorization": f"Bearer {KEYS.get(key, key)}"}
        if session_id:
            h["X-AICL-Session"] = session_id
        if scenario:
            h["X-Mock-Scenario"] = scenario
        if headers:
            h |= headers

        if raw_body is not None:
            payload = raw_body
        else:
            payload = {"tool": tool, "arguments": arguments if arguments is not None else {}}
            if session_id and "X-AICL-Session" not in (headers or {}):
                payload["session_id"] = session_id
            if caller_agent:
                payload["caller_agent"] = caller_agent

        return await self.client.post("/v1/tools/invoke", json=payload, headers=h)

    async def events(self):
        await self.app.state.runtime.audit.stop()
        await self.app.state.runtime.audit.start()
        return list(iter_events(self.audit_path))

    async def request_event(self, response):
        rid = response.headers["X-AICL-Request-Id"]
        return next(e for e in await self.events() if e.request_id == rid)


@asynccontextmanager
async def serve_tool_gw(tmp_path, env=ENV, policy_overlay=None, **kw):
    llm_mock, _ = make_fake_upstream()
    tools_mock, tool_calls = make_mock_tools()
    audit = tmp_path / "audit.jsonl"
    app = create_app(
        write_policy(tmp_path, policy_overlay),
        env=env,
        base_dir=REPO,
        audit_path=audit,
        upstream_transport=httpx.ASGITransport(llm_mock),
        tool_transport=httpx.ASGITransport(tools_mock),
        **kw,
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://aicl") as client,
    ):
        yield ToolGateway(app, client, tool_calls, audit)


@pytest.fixture
async def gw(tmp_path):
    async with serve_tool_gw(tmp_path) as g:
        yield g


# --- Happy path -----------------------------------------------------------------------------------


async def test_allowed_tool_with_valid_arguments_succeeds(gw):
    r = await gw.invoke("search_docs", {"query": "how to reset password"})
    assert r.status_code == 200
    data = r.json()
    assert data["tool"] == "search_docs"
    assert "Search results for: how to reset password" in data["output"]
    assert r.headers["X-AICL-Action"] == "allow"
    assert r.headers["X-AICL-Policy-Version"] == gw.app.state.runtime.policy.version
    assert float(r.headers["X-AICL-Overhead-Ms"]) >= 0

    assert len(gw.tool_calls) == 1
    assert gw.tool_calls[0]["body"]["arguments"] == {"query": "how to reset password"}

    e = await gw.request_event(r)
    assert e.endpoint == "tool_invoke"
    assert e.identity == "support-agent-01"
    assert e.role == "support_agent"
    assert e.profile == "balanced"
    assert e.final_action == Action.allow
    assert e.upstream_called is True
    # Ingress and tool_call decisions recorded
    ctrl_ids = {d.control_id for d in e.decisions}
    assert "C-TOOL-ACL" in ctrl_ids


# --- Security: Tool ACL & Schema validation (TH-07) ----------------------------------------------


async def test_tool_call_invalid_schema_is_blocked(gw):
    # search_docs requires "query" in arg_schema
    r = await gw.invoke("search_docs", {"wrong_arg": "foo"})
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "aicl_blocked"
    assert err["control_id"] == "C-TOOL-ACL"
    assert err["threat_ids"] == ["TH-07"]
    assert len(gw.tool_calls) == 0  # Tool backend never called

    e = await gw.request_event(r)
    assert e.final_action == Action.block
    assert e.upstream_called is False


async def test_unauthorized_tool_for_role_is_blocked(gw):
    # support_agent only has [search_docs, send_email], not fetch_url or run_shell
    r = await gw.invoke("run_shell", {"cmd": "ls -la"})
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "aicl_blocked"
    assert err["control_id"] == "C-TOOL-ACL"
    assert err["threat_ids"] == ["TH-07"]
    assert len(gw.tool_calls) == 0


async def test_admin_wildcard_can_invoke_all_tools(gw):
    r = await gw.invoke("run_shell", {"cmd": "uptime"}, key="admin")
    assert r.status_code == 200
    assert r.json()["output"] == "Executed command: uptime"


async def test_unknown_tool_returns_400_bad_request(gw):
    # admin has "*" in role tools, but "nonexistent_tool" is not in policy tools
    r = await gw.invoke("nonexistent_tool", {}, key="admin")
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["type"] == "aicl_bad_request"
    assert "unknown tool 'nonexistent_tool'" in err["message"]


# --- Security: Taint tracking (TH-19) -------------------------------------------------------------


async def test_untrusted_tool_taints_session_and_blocks_privileged_tool(gw):
    session_id = "sess-taint-test"
    # Step 1: invoke search_docs (output_trust: untrusted)
    r1 = await gw.invoke("search_docs", {"query": "untrusted document"}, session_id=session_id)
    assert r1.status_code == 200
    # Session is now marked tainted
    assert (await gw.app.state.runtime.state.get_session(session_id)).tainted is True

    # Step 2: invoke send_email (privilege: high) in the tainted session -> blocked by C-TAINT
    r2 = await gw.invoke(
        "send_email",
        {"to": "target@example.com", "subject": "hi", "body": "leak"},
        session_id=session_id,
    )
    assert r2.status_code == 403
    err = r2.json()["error"]
    assert err["type"] == "aicl_blocked"
    assert err["control_id"] == "C-TAINT"
    assert err["threat_ids"] == ["TH-19"]

    # Step 3: in a clean untainted session, send_email is permitted
    r3 = await gw.invoke(
        "send_email",
        {"to": "target@example.com", "subject": "hi", "body": "clean"},
        session_id="sess-clean-other",
    )
    assert r3.status_code == 200


# --- Security: Output Scanning & Redaction in tool_result stage (TH-04, TH-05) --------------------


async def test_pii_in_tool_output_is_redacted(gw):
    # Mock tool returns PII (email, PESEL)
    r = await gw.invoke("search_docs", {"query": "customer"}, scenario="leak_pii")
    assert r.status_code == 200
    assert r.headers["X-AICL-Action"] == "redact"
    output = r.json()["output"]
    assert "jan.kowalski@example.com" not in output
    assert "[REDACTED:email]" in output
    assert "44051401458" not in output
    assert "[REDACTED:pesel]" in output

    e = await gw.request_event(r)
    pii = next(d for d in e.decisions if d.control_id == "C-PII-OUT")
    assert pii.action == Action.redact
    assert "jan.kowalski" not in json.dumps(e.model_dump(mode="json"))


async def test_secret_in_tool_output_is_redacted_in_balanced(gw):
    r = await gw.invoke("search_docs", {"query": "credentials"}, scenario="leak_secret")
    assert r.status_code == 200
    assert r.headers["X-AICL-Action"] == "redact"
    output = r.json()["output"]
    assert "AKIA" not in output
    assert "[REDACTED:aws_access_key]" in output


async def test_strict_profile_blocks_secret_in_tool_output(tmp_path):
    # researcher has profile strict
    async with serve_tool_gw(tmp_path) as g:
        r = await g.invoke(
            "fetch_url",
            {"url": "http://internal/doc"},
            key="research",
            scenario="leak_secret",
        )
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "aicl_blocked"
    assert err["control_id"] == "C-SECRET-OUT"
    assert err["threat_ids"] == ["TH-04"]


# --- Security: Runaway loops (TH-13) -------------------------------------------------------------


async def test_loop_guard_blocks_repeated_identical_tool_invocations(gw):
    session = "s-tool-loop"
    args = {"query": "same query repeatedly"}

    # Policy allows 3 identical calls in 60s
    for _ in range(3):
        r = await gw.invoke("search_docs", args, session_id=session)
        assert r.status_code == 200

    # 4th identical call is blocked by C-LOOP
    r4 = await gw.invoke("search_docs", args, session_id=session)
    assert r4.status_code == 403
    err = r4.json()["error"]
    assert err["type"] == "aicl_blocked"
    assert err["control_id"] == "C-LOOP"
    assert err["threat_ids"] == ["TH-13"]


# --- Security: Budgets and Rate Limits (TH-11, TH-12) --------------------------------------------


async def test_rate_limit_exceeded_returns_429(tmp_path):
    overlay = {"budgets": {"support_default": {"max_requests_per_minute": 2}}}
    async with serve_tool_gw(tmp_path, policy_overlay=overlay) as g:
        # First 2 requests succeed
        assert (await g.invoke("search_docs", {"query": "1"})).status_code == 200
        assert (await g.invoke("search_docs", {"query": "2"})).status_code == 200
        # 3rd request exceeds RPM -> 429
        r3 = await g.invoke("search_docs", {"query": "3"})
        assert r3.status_code == 429
        err = r3.json()["error"]
        assert err["type"] == "aicl_budget_exceeded"
        assert err["control_id"] == "C-BUDGET"


# --- Authentication & Request validation (TH-08) -------------------------------------------------


async def test_missing_or_invalid_auth_key(gw):
    r = await gw.invoke("search_docs", {"query": "test"}, key="invalid_key")
    assert r.status_code == 401
    err = r.json()["error"]
    assert err["type"] == "aicl_auth_failed"
    assert err["control_id"] == "C-AUTH"


async def test_caller_agent_mismatch_is_rejected(gw):
    # key belongs to support-agent-01, but caller_agent claims admin
    r = await gw.invoke("search_docs", {"query": "test"}, key="support", caller_agent="admin")
    assert r.status_code == 401
    assert r.json()["error"]["type"] == "aicl_auth_failed"


async def test_bad_request_payloads(gw):
    # Invalid JSON
    r = await gw.client.post(
        "/v1/tools/invoke",
        content=b"not json",
        headers={"Authorization": "Bearer k-support", "Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "aicl_bad_request"

    # Missing "tool" field
    r2 = await gw.client.post(
        "/v1/tools/invoke",
        json={"arguments": {}},
        headers={"Authorization": "Bearer k-support"},
    )
    assert r2.status_code == 400
    assert "tool" in r2.json()["error"]["message"]


# --- Upstream errors -----------------------------------------------------------------------------


async def test_tool_backend_error_returns_502(gw):
    r = await gw.invoke("search_docs", {"query": "x"}, scenario="error:500")
    assert r.status_code == 502
    assert r.json()["error"]["type"] == "aicl_upstream_error"


async def test_unconfigured_backend_url_returns_502(tmp_path):
    # AICL_TOOL_DOCS_URL unset
    env = {k: v for k, v in ENV.items() if k != "AICL_TOOL_DOCS_URL"}
    async with serve_tool_gw(tmp_path, env=env) as g:
        r = await g.invoke("search_docs", {"query": "x"})
    assert r.status_code == 502
    assert "not configured" in r.json()["error"]["message"]

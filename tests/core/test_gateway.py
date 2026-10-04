"""End-to-end through the real app, real controls and engine, with an in-memory fake upstream."""

import json
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fake_upstream import make_fake_upstream
from policy_files import merge, write_policy

from aicl.app import create_app
from aicl.audit import iter_events
from aicl.models import Action, Decision, Stage

REPO = Path(__file__).parents[2]
KEYS = {"support": "k-support", "research": "k-research", "admin": "k-admin"}
ENV = {
    "AICL_KEY_SUPPORT": KEYS["support"],
    "AICL_KEY_RESEARCH": KEYS["research"],
    "AICL_KEY_ADMIN": KEYS["admin"],
    "AICL_UPSTREAM_MOCK_URL": "http://mock",
}
AWS = "AKIA" + "Z7Q2M4XK9P3L8W1N"  # split so secret scanners don't flag the repo


class Gateway:
    def __init__(self, app, client, calls, audit_path):
        self.app, self.client, self.calls, self.audit_path = app, client, calls, audit_path

    async def chat(
        self, content="Hello", *, key="support", model="mock-commercial", scenario=None, headers=None, **body
    ):
        h = {"Authorization": f"Bearer {KEYS.get(key, key)}"} | (headers or {})
        if scenario:
            h["X-Mock-Scenario"] = scenario
        payload = {"model": model, "messages": [{"role": "user", "content": content}]} | body
        return await self.client.post("/v1/chat/completions", json=payload, headers=h)

    async def events(self):
        await self.app.state.runtime.audit.stop()  # flush
        await self.app.state.runtime.audit.start()
        return list(iter_events(self.audit_path))

    async def request_event(self, response):
        rid = response.headers["X-AICL-Request-Id"]
        return next(e for e in await self.events() if e.request_id == rid)


@asynccontextmanager
async def serve(tmp_path, env=ENV, policy_overlay=None, **kw):
    """Started gateway wired to a fresh fake upstream. `policy_overlay` is deep-merged into
    the default policy and written to a temp file (the compiled policy itself is immutable).
    The semantic judge is disabled so no test talks to Ollama."""
    upstream, calls = make_fake_upstream()
    audit = tmp_path / "audit.jsonl"
    app = create_app(
        write_policy(tmp_path, policy_overlay),
        env=env,
        base_dir=REPO,
        audit_path=audit,
        upstream_transport=httpx.ASGITransport(upstream),
        **kw,
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://aicl") as client,
    ):
        yield Gateway(app, client, calls, audit)


@pytest.fixture
async def gw(tmp_path):
    async with serve(tmp_path) as g:
        yield g


# --- happy path -----------------------------------------------------------------------------------


async def test_clean_request_passes_through(gw):
    r = await gw.chat("What are your opening hours?")
    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"] == "What are your opening hours?"
    assert r.headers["X-AICL-Action"] == "allow"
    assert r.headers["X-AICL-Policy-Version"] == gw.app.state.runtime.policy.version
    assert float(r.headers["X-AICL-Overhead-Ms"]) >= 0

    sent = gw.calls[0]
    assert sent["body"]["stream"] is False
    assert sent["authorization"] is None  # client key never leaves the gateway

    e = await gw.request_event(r)
    assert e.identity == "support-agent-01" and e.role == "support_agent" and e.profile == "balanced"
    assert e.final_action == Action.allow and e.upstream_called
    assert e.feed_version == "2026-10-03.2"
    assert e.usage.prompt_tokens == 100 and e.usage.cost_usd == pytest.approx(0.000125)
    assert {d.control_id for d in e.decisions} >= {"C-PII-IN", "C-PII-OUT"}


async def test_mock_scenario_header_is_forwarded(gw):
    r = await gw.chat("hi", scenario="fixed:Hello from mock")
    assert r.json()["choices"][0]["message"]["content"] == "Hello from mock"
    assert gw.calls[0]["scenario"] == "fixed:Hello from mock"


async def test_session_header_is_used(gw):
    r = await gw.chat("hi", headers={"X-AICL-Session": "s-123"})
    assert (await gw.request_event(r)).session_id == "s-123"


# --- real controls ---------------------------------------------------------------------------------


async def test_pii_in_model_output_is_redacted(gw):
    r = await gw.chat("Who is the customer?", scenario="fixed:The customer is jan.kowalski@example.com")
    assert r.status_code == 200 and r.headers["X-AICL-Action"] == "redact"
    content = r.json()["choices"][0]["message"]["content"]
    assert "jan.kowalski@example.com" not in content and "[REDACTED:email]" in content

    e = await gw.request_event(r)
    pii = next(d for d in e.decisions if d.control_id == "C-PII-OUT")
    assert pii.action == Action.redact and pii.threat_ids == ["TH-05"]
    assert "jan.kowalski" not in json.dumps(e.model_dump(mode="json"))


async def test_pii_in_user_input_is_redacted_before_upstream(gw):
    r = await gw.chat("My email is jan.kowalski@example.com, help me")
    assert r.status_code == 200
    # messages[0] is the system prompt with the canary (C-CANARY inject_into_system_prompt)
    forwarded = next(m["content"] for m in gw.calls[0]["body"]["messages"] if m["role"] == "user")
    assert "jan.kowalski@example.com" not in forwarded and "[REDACTED:email]" in forwarded


async def test_strict_profile_blocks_and_never_calls_upstream(gw):
    r = await gw.chat("My PESEL is 44051401458", key="research", model="ollama-local")
    assert r.status_code == 403
    err = r.json()["error"]
    assert (
        err["type"] == "aicl_blocked" and err["control_id"] == "C-PII-IN" and err["threat_ids"] == ["TH-03"]
    )
    assert err["request_id"] == r.headers["X-AICL-Request-Id"]
    assert r.headers["X-AICL-Action"] == "block"
    assert gw.calls == []
    e = await gw.request_event(r)
    assert e.final_action == Action.block and not e.upstream_called


async def test_encoded_secret_in_output_is_blocked(gw):
    import base64

    leak = base64.b64encode(f"key={AWS}".encode()).decode()
    r = await gw.chat("hi", scenario=f"fixed:here you go {leak}")
    assert r.status_code == 403 and r.json()["error"]["control_id"] == "C-SECRET-OUT"
    assert leak not in r.text


# --- auth and request errors -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic k-support"}]
)
async def test_auth_failures(gw, headers):
    r = await gw.client.post(
        "/v1/chat/completions", json={"model": "mock-commercial", "messages": []}, headers=headers
    )
    assert r.status_code == 401 and r.json()["error"]["type"] == "aicl_auth_failed"
    e = await gw.request_event(r)
    assert e.identity is None and e.final_action == Action.block
    assert e.decisions[0].control_id == "C-AUTH" and e.decisions[0].threat_ids == ["TH-08"]


async def test_agent_impersonation_is_rejected(gw):
    r = await gw.chat("hi", headers={"X-AICL-Agent": "admin"})
    assert r.status_code == 401
    assert (await gw.chat("hi", headers={"X-AICL-Agent": "support-agent-01"})).status_code == 200


@pytest.mark.parametrize(
    "payload, fragment",
    [
        (b"not json", "valid JSON"),
        (b"[1, 2]", "JSON object"),
        (b'{"model": "mock-commercial", "messages": []}', "messages"),
        (b'{"messages": [{"role": "user", "content": "x"}]}', "model"),
        (b'{"model": "mock-commercial", "messages": [{"role": "wizard", "content": "x"}]}', "wizard"),
    ],
)
async def test_bad_requests(gw, payload, fragment):
    r = await gw.client.post(
        "/v1/chat/completions",
        content=payload,
        headers={"Authorization": "Bearer k-support", "Content-Type": "application/json"},
    )
    assert r.status_code == 400 and r.json()["error"]["type"] == "aicl_bad_request"
    assert fragment in r.json()["error"]["message"]
    e = await gw.request_event(r)
    assert e.final_action is None and fragment in e.error


async def test_unknown_model(gw):
    # Models missing from the policy allowlist are stopped by C-MODEL-ALLOW (TH-06),
    # also for a wildcard role: "*" means any model defined in the policy.
    for key in ("support", "admin"):
        r = await gw.chat("x", key=key, model="gpt-9")
        assert r.status_code == 403 and r.json()["error"]["control_id"] == "C-MODEL-ALLOW"
    assert gw.calls == []


async def test_unknown_model_without_allowlist_control_is_bad_request(tmp_path):
    overlay = {"controls": {"model_allowlist": {"enabled": False}}}
    async with serve(tmp_path, policy_overlay=overlay) as g:
        r = await g.chat("x", key="admin", model="gpt-9")
    assert r.status_code == 400 and "unknown model" in r.json()["error"]["message"]


@pytest.mark.parametrize("scenario", ["error:500", "error:404"])
async def test_upstream_failure_is_502(gw, scenario):
    r = await gw.chat("hi", scenario=scenario)
    assert r.status_code == 502 and r.json()["error"]["type"] == "aicl_upstream_error"
    assert "HTTP" in (await gw.request_event(r)).error


async def test_unconfigured_upstream_is_502(tmp_path):
    env = {k: v for k, v in ENV.items() if k != "AICL_UPSTREAM_MOCK_URL"}
    async with serve(tmp_path, env=env) as g:
        r = await g.chat("x")
    assert r.status_code == 502 and "not configured" in r.json()["error"]["message"]


# --- message shapes, streaming, tool calls ---------------------------------------------------------


async def test_content_parts_and_tool_messages_are_scanned(gw):
    messages = [
        {"role": "system", "content": "You are helpful."},
        {
            "role": "user",
            "content": [{"type": "text", "text": "summarise"}, {"type": "image_url", "image_url": {}}],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "contact: jan.kowalski@example.com"},
        {"role": "user", "content": "go"},
    ]
    r = await gw.client.post("/v1/chat/completions", headers={"Authorization": "Bearer k-support"},
                             json={"model": "mock-commercial", "messages": messages})  # fmt: skip
    assert r.status_code == 200
    forwarded = gw.calls[0]["body"]["messages"]
    assert forwarded[0]["content"].startswith("You are helpful.")  # + the canary instruction
    assert "[REDACTED:email]" in forwarded[2]["content"]


async def test_stream_true_gets_pseudo_sse(gw):
    r = await gw.chat("stream me", stream=True)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    lines = [ln for ln in r.text.split("\n") if ln.startswith("data: ")]
    assert lines[-1] == "data: [DONE]"
    first = json.loads(lines[0][6:])
    assert first["object"] == "chat.completion.chunk"
    assert first["choices"][0]["delta"]["content"] == "stream me"
    assert gw.calls[0]["body"]["stream"] is False


async def test_proposed_tool_calls_run_tool_call_stage(tmp_path):
    seen = []

    class ToolGuard:
        id = "C-TOOL-ACL"
        stages = (Stage.tool_call,)
        priority = 10

        async def evaluate(self, ctx, cfg):
            seen.append((ctx.tool, ctx.tool_args))
            action = Action.block if ctx.tool == "run_shell" else Action.allow
            return Decision(
                control_id=self.id, threat_ids=["TH-07"], action=action, reason="tool not allowed"
            )

    async with serve(tmp_path, controls={"C-TOOL-ACL": ToolGuard()}) as g:
        ok = await g.chat("x", scenario='call_tool:search_docs:{"query": "refunds"}')
        blocked = await g.chat("x", scenario='call_tool:run_shell:{"cmd": "rm -rf /"}')
    assert ok.status_code == 200
    assert ok.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "search_docs"
    assert blocked.status_code == 403 and blocked.json()["error"]["control_id"] == "C-TOOL-ACL"
    assert seen == [("search_docs", {"query": "refunds"}), ("run_shell", {"cmd": "rm -rf /"})]


async def test_proposed_tool_call_with_secret_is_redacted_in_balanced(gw):
    # Model proposes a tool call containing an AWS secret in arguments
    r = await gw.chat("x", scenario='call_tool:search_docs:{"query": "my key is AKIA1234567890123456"}')
    assert r.status_code == 200
    assert r.headers["X-AICL-Action"] == "redact"
    args_json = r.json()["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert "AKIA" not in args_json
    assert "[REDACTED:aws_access_key]" in args_json


async def test_proposed_tool_call_with_secret_is_blocked_in_strict(tmp_path):
    # In strict profile, model proposing a secret in tool call is blocked
    overlay = {
        "identities": [
            {
                "id": "support-agent-01",
                "api_key_env": "AICL_KEY_SUPPORT",
                "role": "support_agent",
                "profile": "strict",
            }
        ]
    }
    async with serve(tmp_path, policy_overlay=overlay) as g:
        r = await g.chat(
            "x",
            scenario='call_tool:search_docs:{"query": "my key is AKIA1234567890123456"}',
        )
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "aicl_blocked"
    assert err["control_id"] == "C-SECRET-OUT"


# --- accounting and startup events -----------------------------------------------------------------


async def test_usage_is_accounted_per_identity(gw):
    await gw.chat("hi")
    await gw.chat("hi", scenario="no_usage")
    await gw.chat("hi", key="nope")  # unauthenticated: not accounted
    usage = await gw.app.state.runtime.state.get_usage("support-agent-01", "day")
    assert usage.requests == 2
    assert usage.prompt_tokens == 100 + len("hi") // 4


async def test_startup_events(gw):
    events = await gw.events()
    started = next(e for e in events if e.type == "policy.reloaded")
    assert started.detail["reason"] == "startup"
    assert started.detail["missing_controls"] == []
    feed = next(e for e in events if e.type == "feed.reloaded")
    assert feed.detail["status"] == "loaded" and feed.feed_version == "2026-10-03.2"


async def test_healthz(gw):
    r = await gw.client.get("/healthz")
    body = r.json()
    assert body["status"] == "ok"
    assert body["policy_version"] == gw.app.state.runtime.policy.version
    assert body["feed_version"] == "2026-10-03.2"
    # AI detectors as configured (public endpoint: no URLs); default policy has no classifier backend
    assert body["detectors"]["classifier"] == {"backend": "none", "ready": False, "error": None}
    assert set(body["detectors"]["judge"]) == {"model", "ready", "timeout_ms"}
    assert body["detectors"]["embedding"]["backend"] == "none"
    assert body["detectors"]["embedding"]["ready"] is False


async def test_disallowed_model_is_blocked_by_c_model_allow(gw):
    # researcher only allows ollama-local; mock-commercial should be blocked at ingress
    r = await gw.chat("hello", key="research", model="mock-commercial")
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "aicl_blocked"
    assert err["control_id"] == "C-MODEL-ALLOW"
    assert err["threat_ids"] == ["TH-06"]
    assert gw.calls == []
    e = await gw.request_event(r)
    assert e.final_action == Action.block and not e.upstream_called
    blocking = [d for d in e.decisions if d.action == Action.block]
    assert [d.control_id for d in blocking] == ["C-MODEL-ALLOW"]


def _size_overlay(**params):
    return {"controls": {"size_limits": {"params": params}}}


async def test_oversized_message_is_blocked_by_c_size(tmp_path):
    async with serve(tmp_path, policy_overlay=_size_overlay(max_chars_per_message=20)) as g:
        r = await g.chat("A" * 50)
    assert r.status_code == 403
    err = r.json()["error"]
    assert err["type"] == "aicl_blocked" and err["control_id"] == "C-SIZE" and err["threat_ids"] == ["TH-20"]
    assert g.calls == []


async def test_oversized_body_is_rejected_before_parsing(tmp_path):
    async with serve(tmp_path, policy_overlay=_size_overlay(max_body_bytes=200)) as g:
        r = await g.chat("A" * 500)
        assert r.status_code == 403
        err = r.json()["error"]
        assert err["control_id"] == "C-SIZE" and err["threat_ids"] == ["TH-20"]
        e = await g.request_event(r)
        assert e.final_action == Action.block and not e.upstream_called
        assert e.decisions[0].matches[0].kind == "body_size_limit"
        assert e.model is None  # rejected before the body was parsed
        assert (await g.chat("short")).status_code == 200


async def test_body_limit_checked_only_after_authentication(tmp_path):
    async with serve(tmp_path, policy_overlay=_size_overlay(max_body_bytes=200)) as g:
        r = await g.chat("A" * 500, key="nope")
    assert r.status_code == 401


async def test_body_limit_respects_flag_and_shadow(tmp_path):
    flag = {
        "controls": {
            "size_limits": {"params": {"max_body_bytes": 200}, "levels": {"balanced": {"action": "flag"}}}
        }
    }
    async with serve(tmp_path, policy_overlay=flag) as g:
        r = await g.chat("A" * 500)
        assert r.status_code == 200 and r.headers["X-AICL-Action"] == "flag"
        assert (await g.request_event(r)).decisions[0].control_id == "C-SIZE"

    shadow = merge(_size_overlay(max_body_bytes=200), {"controls": {"size_limits": {"mode": "shadow"}}})
    async with serve(tmp_path, policy_overlay=shadow) as g:
        r = await g.chat("A" * 500)
        assert r.status_code == 200 and r.headers["X-AICL-Action"] == "allow"
        e = await g.request_event(r)
        assert e.shadow and e.would_have_action == Action.block


async def test_tool_message_taints_session_and_blocks_privileged_tool(gw):
    session = {"X-AICL-Session": "s-taint"}
    r = await gw.client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer k-support"} | session,
        json={
            "model": "mock-commercial",
            "messages": [{"role": "user", "content": "read it"}, {"role": "tool", "content": "doc text"}],
        },
    )
    assert r.status_code == 200
    assert (await gw.app.state.runtime.state.get_session("s-taint")).tainted

    email = 'call_tool:send_email:{"to": "x@example.org", "subject": "s", "body": "b"}'
    r = await gw.chat("send it", scenario=email, headers=session)
    assert r.status_code == 403 and r.json()["error"]["control_id"] == "C-TAINT"
    # an untainted session may still use the same tool
    assert (
        await gw.chat("send it", scenario=email, headers={"X-AICL-Session": "s-clean"})
    ).status_code == 200


async def test_rate_limit_answers_429_and_emits_budget_event(tmp_path):
    overlay = {"budgets": {"support_default": {"max_requests_per_minute": 2}}}
    async with serve(tmp_path, policy_overlay=overlay) as g:
        assert [(await g.chat("hi")).status_code for _ in range(2)] == [200, 200]
        r = await g.chat("hi")
        assert r.status_code == 429
        err = r.json()["error"]
        assert err["type"] == "aicl_budget_exceeded" and err["control_id"] == "C-BUDGET"
        assert r.headers["X-AICL-Action"] == "block"
        events = await g.events()
        budget = [e for e in events if e.type == "budget.exceeded"]
        assert len(budget) == 1 and budget[0].identity == "support-agent-01"
        assert budget[0].request_id == r.headers["X-AICL-Request-Id"]


async def test_admin_policy_validate_and_reload(gw):
    admin = {"Authorization": "Bearer k-admin"}
    valid = (REPO / "policies" / "default.yaml").read_text(encoding="utf-8")
    r = await gw.client.post("/admin/policy/validate", content=valid, headers=admin)
    assert r.status_code == 200 and r.json()["valid"] is True

    r = await gw.client.post("/admin/policy/validate", content="version: 1\ncontorls: {}\n", headers=admin)
    assert r.status_code == 400 and any("contorls" in e for e in r.json()["errors"])

    r = await gw.client.post("/admin/policy/reload", headers=admin)
    assert r.status_code == 200 and r.json()["reloaded"] is False  # file unchanged

    for headers in ({"Authorization": "Bearer k-support"}, {}):
        assert (
            await gw.client.post("/admin/policy/validate", content=valid, headers=headers)
        ).status_code in (
            401,
            403,
        )


async def test_v1_chat_alias_works(gw):
    r = await gw.client.post(
        "/v1/chat",
        headers={"Authorization": "Bearer k-support"},
        json={
            "model": "mock-commercial",
            "messages": [{"role": "user", "content": "ping via /v1/chat"}],
        },
    )
    assert r.status_code == 200
    assert r.headers["X-AICL-Action"] == "allow"
    assert "choices" in r.json()


async def test_admin_can_test_as_identity_in_playground(gw):
    # Admin testing as support-agent-01 via X-AICL-Agent succeeds
    r = await gw.client.post(
        "/v1/chat",
        headers={"Authorization": "Bearer k-admin", "X-AICL-Agent": "support-agent-01"},
        json={
            "model": "mock-commercial",
            "messages": [{"role": "user", "content": "hello from playground"}],
        },
    )
    assert r.status_code == 200
    event = await gw.request_event(r)
    assert event.identity == "support-agent-01"
    assert event.role == "support_agent"

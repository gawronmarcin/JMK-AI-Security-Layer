"""End-to-end through the real app, real controls and engine, with an in-memory fake upstream."""

import json
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fake_upstream import make_fake_upstream

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
async def serve(tmp_path, env=ENV, **kw):
    """Started gateway wired to a fresh fake upstream."""
    upstream, calls = make_fake_upstream()
    audit = tmp_path / "audit.jsonl"
    app = create_app(
        REPO / "policies" / "default.yaml",
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
    assert e.feed_version == "2026-10-03.1"
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
    forwarded = gw.calls[0]["body"]["messages"][0]["content"]
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
        (b'{"model": "gpt-9", "messages": [{"role": "user", "content": "x"}]}', "unknown model"),
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
    assert forwarded[0]["content"] == "You are helpful."
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
        ok = await g.chat("x", scenario='tool_call:search_docs:{"query": "refunds"}')
        blocked = await g.chat("x", scenario='tool_call:run_shell:{"cmd": "rm -rf /"}')
    assert ok.status_code == 200
    assert ok.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "search_docs"
    assert blocked.status_code == 403 and blocked.json()["error"]["control_id"] == "C-TOOL-ACL"
    assert seen == [("search_docs", {"query": "refunds"}), ("run_shell", {"cmd": "rm -rf /"})]


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
    assert "C-INJ-PAT" in started.detail["missing_controls"]
    feed = next(e for e in events if e.type == "feed.reloaded")
    assert feed.detail["status"] == "loaded" and feed.feed_version == "2026-10-03.1"


async def test_healthz(gw):
    r = await gw.client.get("/healthz")
    assert r.json() == {
        "status": "ok",
        "policy_version": gw.app.state.runtime.policy.version,
        "feed_version": "2026-10-03.1",
    }


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
    assert e.decisions[0].control_id == "C-MODEL-ALLOW"


async def test_oversized_message_is_blocked_by_c_size(tmp_path):
    upstream, calls = make_fake_upstream()
    audit = tmp_path / "audit.jsonl"
    app = create_app(
        REPO / "policies" / "default.yaml",
        env=ENV,
        base_dir=REPO,
        audit_path=audit,
        upstream_transport=httpx.ASGITransport(upstream),
    )
    # Update size_limits params to max_chars_per_message = 20
    policy = app.state.runtime.policy
    cfg = policy.level_config("C-SIZE", "balanced")
    if cfg is not None:
        cfg.max_chars_per_message = 20

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://test") as client:
            h = {"Authorization": "Bearer k-support"}
            payload = {"model": "mock-commercial", "messages": [{"role": "user", "content": "A" * 50}]}
            r = await client.post("/v1/chat/completions", json=payload, headers=h)
            assert r.status_code == 403
            err = r.json()["error"]
            assert err["type"] == "aicl_blocked"
            assert err["control_id"] == "C-SIZE"
            assert err["threat_ids"] == ["TH-20"]
            assert calls == []


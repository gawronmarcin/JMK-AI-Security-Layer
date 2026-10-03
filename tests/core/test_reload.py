"""Hot reload (§9): policy and feed edits take effect on the next request, without restart."""

import asyncio
import shutil
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import yaml
from fake_upstream import make_fake_upstream
from policy_files import JUDGE_DISABLED, write_policy

from aicl.app import create_app
from aicl.audit import iter_events

REPO = Path(__file__).parents[2]
ENV = {"AICL_KEY_SUPPORT": "k-support", "AICL_KEY_ADMIN": "k-admin", "AICL_UPSTREAM_MOCK_URL": "http://mock"}
LEAK = "fixed:The customer is jan.kowalski@example.com"


class Env:
    def __init__(self, app, client, tmp):
        self.app, self.client, self.tmp = app, client, tmp
        self.rt = app.state.runtime
        self.policy_file = tmp / "policy.yaml"
        self.feed_file = tmp / "feeds" / "attacks.yaml"

    def edit_policy(self, fn):
        data = yaml.safe_load(self.policy_file.read_text(encoding="utf-8"))
        fn(data)
        self.policy_file.write_text(yaml.safe_dump(data), encoding="utf-8")

    async def chat(self, scenario=LEAK):
        return await self.client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer k-support", "X-Mock-Scenario": scenario},
            json={"model": "mock-commercial", "messages": [{"role": "user", "content": "who?"}]},
        )

    async def events(self, type_):
        await self.rt.audit.stop()
        await self.rt.audit.start()
        return [e for e in iter_events(self.tmp / "audit.jsonl") if e.type == type_]


@asynccontextmanager
async def gateway(tmp_path, reload_interval=None):
    write_policy(tmp_path)  # tmp_path/policy.yaml, semantic judge disabled
    (tmp_path / "feeds").mkdir()
    shutil.copy(REPO / "feeds" / "attacks.yaml", tmp_path / "feeds" / "attacks.yaml")
    upstream, _ = make_fake_upstream()
    app = create_app(
        tmp_path / "policy.yaml",
        env=ENV,
        base_dir=tmp_path,
        audit_path=tmp_path / "audit.jsonl",
        upstream_transport=httpx.ASGITransport(upstream),
        reload_interval=reload_interval,
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://aicl") as client,
    ):
        yield Env(app, client, tmp_path)


def pii_action(action):
    def fn(data):
        data["controls"]["pii_output"]["levels"]["balanced"]["action"] = action

    return fn


async def eventually(predicate, timeout=3.0):
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("condition not met in time")
        await asyncio.sleep(0.02)


async def test_policy_change_applies_to_next_request(tmp_path):
    async with gateway(tmp_path) as g:
        r = await g.chat()
        old_version = r.headers["X-AICL-Policy-Version"]
        assert r.status_code == 200 and r.headers["X-AICL-Action"] == "redact"

        g.edit_policy(pii_action("block"))
        assert g.rt.reload_policy() is True

        r = await g.chat()
        assert r.status_code == 403 and r.json()["error"]["control_id"] == "C-PII-OUT"
        assert r.headers["X-AICL-Policy-Version"] != old_version
        reloaded = (await g.events("policy.reloaded"))[-1]
        assert reloaded.detail["reason"] == "file_changed"
        assert reloaded.detail["previous_version"] == old_version


async def test_invalid_policy_is_rejected_and_old_one_stays(tmp_path):
    async with gateway(tmp_path) as g:
        version = g.rt.policy.version
        g.edit_policy(pii_action("blok"))
        assert g.rt.reload_policy() is False

        assert g.rt.policy.version == version
        r = await g.chat()
        assert r.status_code == 200 and r.headers["X-AICL-Action"] == "redact"
        rejected = (await g.events("policy.rejected"))[-1]
        assert rejected.policy_version == version
        assert any("pii_output.levels.balanced.action" in e for e in rejected.detail["errors"])


async def test_unreadable_yaml_is_rejected(tmp_path):
    async with gateway(tmp_path) as g:
        g.policy_file.write_text("controls: [unclosed", encoding="utf-8")
        assert g.rt.reload_policy() is False
        assert "YAML syntax" in (await g.events("policy.rejected"))[-1].detail["errors"][0]


async def test_unchanged_content_is_not_reloaded(tmp_path):
    async with gateway(tmp_path) as g:
        g.policy_file.write_text(g.policy_file.read_text(encoding="utf-8"), encoding="utf-8")
        assert g.rt.reload_policy() is False


async def test_removed_control_is_disabled_with_warning(tmp_path):
    async with gateway(tmp_path) as g:
        g.edit_policy(lambda d: d["controls"].pop("pii_output"))
        assert g.rt.reload_policy() is True
        r = await g.chat()
        assert r.status_code == 200 and "jan.kowalski@example.com" in r.text
        assert (await g.events("policy.reloaded"))[-1].detail["removed_controls"] == ["pii_output"]


async def test_watcher_picks_up_policy_and_feed_edits(tmp_path):
    async with gateway(tmp_path, reload_interval=0.05) as g:
        version = g.rt.policy.version
        g.edit_policy(pii_action("block"))
        await eventually(lambda: g.rt.policy.version != version)
        assert (await g.chat()).status_code == 403

        feed = yaml.safe_load(g.feed_file.read_text(encoding="utf-8"))
        feed["feed_version"] = "2026-10-04.1"
        g.feed_file.write_text(yaml.safe_dump(feed), encoding="utf-8")
        await eventually(lambda: g.rt.feeds.current().version == "2026-10-04.1")
        assert (await g.client.get("/healthz")).json()["feed_version"] == "2026-10-04.1"


async def test_budget_counters_survive_reload(tmp_path):
    async with gateway(tmp_path) as g:
        await g.chat("fixed:hello")
        g.edit_policy(pii_action("flag"))
        assert g.rt.reload_policy() is True
        await g.chat("fixed:hello")
        assert (await g.rt.state.get_usage("support-agent-01", "day")).requests == 2


async def test_semantic_judge_is_configured_on_start_and_on_change(tmp_path, monkeypatch):
    from aicl.controls import injection_semantic

    seen = []
    monkeypatch.setattr(injection_semantic, "configure", lambda settings, **kw: seen.append(settings))
    async with gateway(tmp_path) as g:
        assert [s.model for s in seen] == [JUDGE_DISABLED] and not seen[0].model_ready

        g.edit_policy(pii_action("block"))  # unrelated change: judge is not rebuilt
        assert g.rt.reload_policy() is True
        assert len(seen) == 1

        g.edit_policy(lambda d: d["semantic"].update(model="qwen2.5:0.5b", timeout_ms=900))
        assert g.rt.reload_policy() is True
        assert seen[-1].model == "qwen2.5:0.5b" and seen[-1].timeout_ms == 900 and seen[-1].model_ready


async def test_broken_listener_does_not_block_reload(tmp_path):
    async with gateway(tmp_path) as g:

        def broken(policy):
            raise RuntimeError("boom")

        g.rt.policy_listeners.append(broken)
        g.edit_policy(pii_action("block"))
        assert g.rt.reload_policy() is True
        assert (await g.chat()).status_code == 403
        assert (await g.events("policy.reloaded"))[-1].detail["listener_errors"] == ["broken: RuntimeError"]


@pytest.mark.parametrize("interval", [None, 0])
async def test_no_watcher_when_disabled(tmp_path, interval):
    async with gateway(tmp_path, reload_interval=interval) as g:
        assert g.rt._watcher is None

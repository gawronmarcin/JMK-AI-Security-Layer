"""Live self-test (aicl/selftest.py): expectations follow the CURRENT policy."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from fake_tools import make_mock_tools
from fake_upstream import make_fake_upstream
from policy_files import write_policy

from aicl.app import create_app
from tests.core.test_mcp import Router
from tests.mocks.mock_mcp import create_app as create_mock_mcp

REPO = Path(__file__).parents[2]
ENV = {
    "AICL_KEY_SUPPORT": "k-support", "AICL_KEY_RESEARCH": "k-research", "AICL_KEY_ADMIN": "k-admin",
    "AICL_UPSTREAM_MOCK_URL": "http://mock-llm",
    "AICL_TOOL_DOCS_URL": "http://mock-tools/search_docs", "AICL_TOOL_FETCH_URL": "http://mock-tools/fetch_url",
    "AICL_TOOL_MAIL_URL": "http://mock-tools/send_email", "AICL_TOOL_SHELL_URL": "http://mock-tools/run_shell",
    "AICL_MCP_DOCS_URL": "http://mock-mcp/mcp",
}
ADMIN = {"Authorization": "Bearer k-admin"}


@asynccontextmanager
async def serve(tmp_path, overlay=None):
    router = Router({"mock-mcp": httpx.ASGITransport(create_mock_mcp()),
                     "mock-tools": httpx.ASGITransport(make_mock_tools()[0])})
    app = create_app(write_policy(tmp_path, overlay), env=ENV, base_dir=REPO, audit_path=tmp_path / "audit.jsonl",
                     upstream_transport=httpx.ASGITransport(make_fake_upstream()[0]), tool_transport=router)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://aicl") as client,
    ):
        yield client


async def _run(client, ids=None):
    r = await client.post("/admin/selftest/run" + (f"?ids={ids}" if ids else ""), headers=ADMIN)
    assert r.status_code == 200, r.text
    return r.json()


def _by_id(report):
    return {r["id"]: r for r in report["results"]}


async def test_reference_policy_passes_every_probe(tmp_path):
    async with serve(tmp_path) as client:
        report = await _run(client)
        failed = [(r["id"], r["note"]) for r in report["results"] if r["verdict"] != "PASS"]
        assert failed == [] and report["summary"]["PASS"] == len(report["results"]) >= 19


async def test_expectations_follow_an_edited_policy(tmp_path):
    overlay = {"controls": {"injection_patterns": {"enabled": False},
                            "pii_input": {"levels": {"balanced": {"action": "block"}}},
                            "secrets_input": {"mode": "shadow"}}}
    async with serve(tmp_path, overlay) as client:
        probes = {p["id"]: p for p in (await client.get("/admin/selftest", headers=ADMIN)).json()["probes"]}
        assert probes["inj-direct"]["expected"]["active"] is False
        assert probes["pii-in"]["expected"]["action"] == "block"
        report = _by_id(await _run(client, "inj-direct,pii-in,secret-in"))
        assert report["inj-direct"]["verdict"] == "PASS" and "off" in report["inj-direct"]["note"]
        assert report["pii-in"]["verdict"] == "PASS" and report["pii-in"]["action"] == "block"
        assert report["secret-in"]["verdict"] == "PASS" and "shadow" in report["secret-in"]["note"]


async def test_a_wrong_outcome_fails(tmp_path, monkeypatch):
    from aicl import selftest

    real = selftest.expected_for

    def lying(policy, probe, profile):  # pretend the policy says "redact" for a block
        exp = real(policy, probe, profile)
        if probe.id == "tool-acl":
            exp.action = "redact"
        return exp

    monkeypatch.setattr(selftest, "expected_for", lying)
    async with serve(tmp_path) as client:
        r = _by_id(await _run(client, "tool-acl"))["tool-acl"]
        assert r["verdict"] == "FAIL" and "expected redact" in r["note"]


async def test_selftest_needs_admin_and_cleans_approvals(tmp_path):
    async with serve(tmp_path, {"taint": {"action": "require_approval"}}) as client:
        assert (await client.post("/admin/selftest/run", headers={"Authorization": "Bearer k-support"})).status_code == 403
        r = _by_id(await _run(client, "taint"))["taint"]
        assert r["verdict"] == "PASS" and r["action"] == "require_approval"
        pending = (await client.get("/admin/approvals?status=pending", headers=ADMIN)).json()["approvals"]
        assert pending == []


@pytest.mark.parametrize("probe", ["inj-direct", "pii-in", "ok-chat"])
async def test_playground_probes_carry_their_prompt(tmp_path, probe):
    async with serve(tmp_path) as client:
        p = {x["id"]: x for x in (await client.get("/admin/selftest", headers=ADMIN)).json()["probes"]}[probe]
        assert p["prompt"] and p["identity"] == "admin" and p["expected"]["action"]


def test_error_of_handles_every_response_shape():
    from aicl.selftest import _error_of

    assert _error_of({"error": {"control_id": "C-X"}}) == {"control_id": "C-X"}       # REST error
    assert _error_of({"result": "plain tool output"}) == {}                           # REST tool result
    assert _error_of({"result": {"isError": True, "_meta": {"aicl": {"control_id": "C-Y"}}}}) == {"control_id": "C-Y"}
    assert _error_of({"result": {"content": []}}) == {}                               # MCP success

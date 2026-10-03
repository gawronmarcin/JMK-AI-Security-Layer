"""Tests for admin endpoints: policy, controls, metrics, events, budgets, exports (ARCHITECTURE.md §5.1, §8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.core.test_gateway import serve


@pytest.fixture
async def gw(tmp_path):
    async with serve(tmp_path) as g:
        yield g


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer k-admin"}


@pytest.fixture
def user_headers() -> dict[str, str]:
    return {"Authorization": "Bearer k-support"}


async def test_probes(gw):
    for endpoint in ("/healthz", "/livez", "/readyz"):
        r = await gw.client.get(endpoint)
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


async def test_dashboard_endpoint(gw):
    r = await gw.client.get("/dashboard", follow_redirects=True)
    assert r.status_code == 200 and "<title>" in r.text


async def test_get_policy(gw, admin_headers, user_headers):
    # Non-admin rejected
    r = await gw.client.get("/admin/policy", headers=user_headers)
    assert r.status_code in (401, 403)

    # Admin allowed
    r = await gw.client.get("/admin/policy", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "version" in data
    assert "policy" in data
    # Ensure api_key_env is masked
    for ident in data["policy"].get("identities", []):
        assert ident["api_key_env"] == "[MASKED]"


async def test_get_controls(gw, admin_headers):
    r = await gw.client.get("/admin/controls", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "controls" in data
    control_ids = {c["id"] for c in data["controls"]}
    assert "C-INJ-PAT" in control_ids
    assert "C-ARTIFACT" in control_ids
    assert "C-CODE-EXEC" in control_ids


async def test_metrics_summary_and_latency(gw, admin_headers):
    # Trigger one chat request to create an audit event
    await gw.chat("hello world")

    # Check summary
    r = await gw.client.get("/admin/metrics/summary", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "security_posture" in data
    assert "totals" in data
    assert data["totals"]["requests"] >= 1

    # Check latency
    r = await gw.client.get("/admin/metrics/latency", headers=admin_headers)
    assert r.status_code == 200
    lat_data = r.json()
    assert "total_overhead_ms" in lat_data
    assert "upstream_ms" in lat_data
    assert "per_control" in lat_data


async def test_metrics_budgets(gw, admin_headers):
    r = await gw.client.get("/admin/metrics/budgets", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "active_usage" in data
    assert "roles" in data


async def test_events_filtering(gw, admin_headers):
    await gw.chat("clean query")
    await gw.chat("another clean query")

    r = await gw.client.get("/admin/events?limit=10", headers=admin_headers)
    assert r.status_code == 200
    data = r.json()
    assert "events" in data
    assert len(data["events"]) >= 1


async def test_export_audit(gw, admin_headers):
    r = await gw.client.get("/admin/export/audit.jsonl", headers=admin_headers)
    assert r.status_code == 200


async def test_latest_report(gw, admin_headers):
    report_file = Path("reports/test_report.json")
    if not report_file.exists():
        report_file.parent.mkdir(parents=True, exist_ok=True)
        report_file.write_text(json.dumps({"totals": {"cases": 1, "passed": 1}}), encoding="utf-8")
    r = await gw.client.get("/admin/reports/latest", headers=admin_headers)
    assert r.status_code == 200

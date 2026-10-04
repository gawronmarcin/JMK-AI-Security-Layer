"""Group C tests: Telemetry incremental event cache and audit export with rotated files."""

from __future__ import annotations

import json

import pytest
from httpx import ASGITransport, AsyncClient

from aicl.admin.telemetry import _EventCache
from aicl.app import create_app
from aicl.audit import AuditWriter, new_event


class DummyRuntime:
    def __init__(self, audit_path):
        self.audit = AuditWriter(audit_path)


@pytest.mark.asyncio
async def test_event_cache_incremental(tmp_path):
    log_file = tmp_path / "audit_cache.jsonl"
    rt = DummyRuntime(log_file)
    cache = _EventCache(rt)

    ev1 = new_event(
        "request",
        request_id="req_01",
        session_id="s1",
        endpoint="chat",
        identity="id1",
        role="r1",
        profile="balanced",
        policy_version="1",
    )
    ev2 = new_event(
        "request",
        request_id="req_02",
        session_id="s1",
        endpoint="chat",
        identity="id1",
        role="r1",
        profile="balanced",
        policy_version="1",
    )

    with log_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(ev1.model_dump(mode="json")) + "\n")

    events = cache.all()
    assert len(events) == 1
    assert events[0].request_id == "req_01"
    offset_1 = cache._offset
    assert offset_1 > 0

    # Append second event
    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(ev2.model_dump(mode="json")) + "\n")

    events = cache.all()
    assert len(events) == 2
    assert events[1].request_id == "req_02"
    assert cache._offset > offset_1

    # Simulate rotation/truncate: rewrite file with only ev2
    with log_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(ev2.model_dump(mode="json")) + "\n")

    events = cache.all()
    assert len(events) == 1
    assert events[0].request_id == "req_02"


@pytest.mark.asyncio
async def test_audit_export_include_rotated(tmp_path):
    audit_file = tmp_path / "audit.jsonl"
    audit_rot1 = tmp_path / "audit.jsonl.1"

    ev_old = new_event(
        "request",
        request_id="req_old",
        session_id="s1",
        endpoint="chat",
        identity="id1",
        role="r1",
        profile="balanced",
        policy_version="1",
    )
    ev_new = new_event(
        "request",
        request_id="req_new",
        session_id="s1",
        endpoint="chat",
        identity="id1",
        role="r1",
        profile="balanced",
        policy_version="1",
    )

    audit_rot1.write_text(json.dumps(ev_old.model_dump(mode="json")) + "\n", encoding="utf-8")
    audit_file.write_text(json.dumps(ev_new.model_dump(mode="json")) + "\n", encoding="utf-8")

    app = create_app(
        env={"AICL_ADMIN_OPEN": "1"},
        audit_path=audit_file,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Default export (active file only)
        r1 = await client.get("/admin/export/audit.jsonl")
        assert r1.status_code == 200
        text1 = r1.text
        assert "req_new" in text1
        assert "req_old" not in text1

        # Export including rotated
        r2 = await client.get("/admin/export/audit.jsonl?include_rotated=true")
        assert r2.status_code == 200
        text2 = r2.text
        assert "req_old" in text2
        assert "req_new" in text2

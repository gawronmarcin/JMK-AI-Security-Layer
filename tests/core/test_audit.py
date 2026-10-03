import json

from aicl.audit import AuditWriter, iter_events, new_event, serialize
from aicl.models import Action, AuditDecision, AuditMatch, Latency, Usage


def _request_event(**over):
    fields = {
        "request_id": "req_1",
        "session_id": "sess_abc",
        "endpoint": "chat",
        "identity": "support-agent-01",
        "role": "support_agent",
        "profile": "balanced",
        "policy_version": "a3f9c1d2e4b7",
        "model": "mock-commercial",
        "final_action": Action.redact,
        "upstream_called": True,
        "decisions": [
            AuditDecision(
                control_id="C-SECRET-OUT",
                threat_ids=["TH-04"],
                action=Action.redact,
                severity="high",
                reason="AWS access key in model output",
                matches=[AuditMatch(kind="aws_access_key", segment_idx=3, masked="AKIA****************")],
                latency_ms=0.21,
            )
        ],
        "latency_ms": Latency(total_overhead=3.4, upstream=812.0, per_control={"C-SECRET-OUT": 0.21}),
        "usage": Usage(prompt_tokens=120, completion_tokens=85, cost_usd=0.000187),
    }
    return new_event("request", **(fields | over))


def test_event_shape_matches_contract():
    data = json.loads(serialize(_request_event(), 65536))
    expected_keys = {
        "ts", "event_id", "request_id", "session_id", "type", "endpoint", "identity", "role", "profile",
        "policy_version", "feed_version", "model", "final_action", "would_have_action", "shadow",
        "upstream_called", "decisions", "latency_ms", "usage", "error", "detail",
    }  # fmt: skip
    assert set(data) == expected_keys
    assert data["ts"].endswith("Z") and data["event_id"].startswith("evt_")
    assert data["final_action"] == "redact"
    assert data["decisions"][0]["matches"][0] == {
        "kind": "aws_access_key",
        "segment_idx": 3,
        "masked": "AKIA****************",
    }


def test_oversized_event_is_truncated_but_readable():
    huge = _request_event()
    huge.decisions[0].reason = "x" * 100_000
    line = serialize(huge, 2048)
    assert len(line.encode()) <= 2048
    data = json.loads(line)
    assert "truncated" in data["error"]
    assert data["decisions"][0]["control_id"] == "C-SECRET-OUT"


async def test_writer_appends_lines_and_notifies_listeners(tmp_path):
    path = tmp_path / "sub" / "audit.jsonl"
    writer = AuditWriter(path)
    seen = []
    writer.add_listener(seen.append)
    writer.add_listener(lambda e: 1 / 0)  # broken listener must not break logging
    await writer.start()
    for i in range(50):
        writer.emit(_request_event(request_id=f"req_{i}"))
    writer.emit(new_event("policy.rejected", detail={"errors": ["controls.x: bad"]}))
    await writer.stop()

    events = list(iter_events(path))
    assert len(events) == 51 and len(seen) == 51
    assert [e.request_id for e in events[:50]] == [f"req_{i}" for i in range(50)]
    assert events[-1].type == "policy.rejected" and events[-1].detail == {"errors": ["controls.x: bad"]}


def test_iter_events_skips_corrupt_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text(serialize(_request_event(), 65536) + "\n{not json\n\n", encoding="utf-8")
    assert len(list(iter_events(path))) == 1

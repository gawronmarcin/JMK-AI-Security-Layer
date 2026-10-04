"""Group C tests: Policy governance, validation of rejected options, control IDs, and audit content none."""

from __future__ import annotations

import pytest

from aicl.audit import AuditWriter, iter_events, new_event
from aicl.models import Action, AuditDecision, AuditMatch
from aicl.policy.loader import PolicyError, parse_policy


def test_reject_throttle_and_downgrade():
    policy_throttle = """
version: 1
active_profile: balanced
mode: enforce
identities: []
roles: {}
budgets:
  bad_budget:
    window: day
    on_exceed: throttle
controls: {}
"""
    with pytest.raises(PolicyError) as exc_info:
        parse_policy(policy_throttle)
    assert any("on_exceed" in e for e in exc_info.value.errors)

    policy_downgrade = """
version: 1
active_profile: balanced
mode: enforce
identities: []
roles: {}
budgets:
  bad_budget:
    window: day
    on_exceed: downgrade_model
controls: {}
"""
    with pytest.raises(PolicyError) as exc_info:
        parse_policy(policy_downgrade)
    assert any("on_exceed" in e for e in exc_info.value.errors)


def test_reject_unknown_control_ids():
    bad_control = """
version: 1
active_profile: balanced
mode: enforce
identities: []
roles: {}
controls:
  weird_control:
    id: C-NONEXISTENT
    enabled: true
    stages: [ingress]
    levels:
      strict: {action: block}
      balanced: {action: block}
      permissive: {action: flag}
"""
    from aicl import registry

    with pytest.raises(PolicyError) as exc_info:
        parse_policy(bad_control, known_controls=registry.all_controls())
    assert any("unknown control id 'C-NONEXISTENT'" in e for e in exc_info.value.errors)


@pytest.mark.asyncio
async def test_audit_content_none_redaction(tmp_path):
    log_file = tmp_path / "audit_none.jsonl"
    writer = AuditWriter(path=log_file, max_event_bytes=65536, content_mode="none")
    await writer.start()

    dec = AuditDecision(
        control_id="C-PII-IN",
        threat_ids=["TH-03"],
        action=Action.block,
        severity="high",
        reason="detected sensitive phone number",
        matches=[AuditMatch(kind="phone_pl", masked="123-456-789")],
    )

    ev = new_event(
        "request",
        request_id="req_test_none",
        session_id="sess_test",
        endpoint="chat",
        identity="user_none",
        role="agent",
        profile="balanced",
        policy_version="1",
        decisions=[dec],
    )

    writer.emit(ev)
    await writer.stop()

    events = list(iter_events(log_file))
    assert len(events) == 1
    read_ev = events[0]
    assert len(read_ev.decisions) == 1
    match = read_ev.decisions[0].matches[0]
    assert match.masked is None or match.masked == ""

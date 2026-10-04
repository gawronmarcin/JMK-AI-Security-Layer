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


# --- the gateway applies these settings, at startup and on hot reload --------------------------

def _gateway_app(tmp_path, overlay=None):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from policy_files import write_policy

    from aicl.app import create_app

    env = {"AICL_KEY_SUPPORT": "k-support", "AICL_KEY_RESEARCH": "k-research", "AICL_KEY_ADMIN": "k-admin"}
    path = write_policy(tmp_path, overlay)
    return create_app(path, env=env, base_dir=Path(__file__).parents[2], audit_path=tmp_path / "audit.jsonl",
                      reload_interval=None), path


def test_typo_in_control_id_is_rejected_at_startup(tmp_path):
    with pytest.raises(PolicyError) as exc_info:
        _gateway_app(tmp_path, {"controls": {"injection_patterns": {"id": "C-INJ-PATT"}}})
    assert any("unknown control id 'C-INJ-PATT'" in e for e in exc_info.value.errors)


def test_typo_in_control_id_is_rejected_on_reload(tmp_path):
    app, path = _gateway_app(tmp_path)
    rt = app.state.runtime
    before = rt.policy.version
    path.write_text(path.read_text(encoding="utf-8").replace("id: C-INJ-PAT", "id: C-INJ-PATT"), encoding="utf-8")
    assert rt.reload_policy() is False
    assert rt.policy.version == before


def test_session_ttl_follows_the_policy_on_reload(tmp_path):
    app, path = _gateway_app(tmp_path)
    rt = app.state.runtime
    assert rt.state.session_ttl == 3600
    path.write_text(path.read_text(encoding="utf-8").replace("session_ttl_seconds: 3600", "session_ttl_seconds: 120"),
                    encoding="utf-8")
    assert rt.reload_policy() is True
    assert rt.state.session_ttl == 120


def test_audit_settings_apply_from_startup(tmp_path):
    app, _ = _gateway_app(tmp_path, {"audit": {"content": "none", "max_file_bytes": 1234, "keep_files": 2}})
    audit = app.state.runtime.audit
    assert (audit.content_mode, audit.max_file_bytes, audit.keep_files) == ("none", 1234, 2)

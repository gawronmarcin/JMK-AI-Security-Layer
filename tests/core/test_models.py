import pytest
from pydantic import ValidationError

from aicl.models import (
    Action,
    AuditDecision,
    Decision,
    Match,
    Origin,
    RequestContext,
    Segment,
    Stage,
    strongest_action,
)


def _ctx(**over):
    base = {
        "request_id": "req_1",
        "session_id": "s1",
        "endpoint": "chat",
        "stage": Stage.input,
        "identity": "support-agent-01",
        "role": "support_agent",
        "profile": "balanced",
        "model": "mock-commercial",
        "segments": [Segment(idx=0, text="Hi", norm="hi", origin=Origin.user)],
        "policy_version": "abc",
    }
    return RequestContext(**(base | over))


def test_precedence():
    assert strongest_action([Action.flag, Action.block, Action.redact]) == Action.block
    assert strongest_action([Action.redact, Action.require_approval]) == Action.require_approval
    assert strongest_action([]) == Action.allow


def test_typo_in_field_is_rejected():
    with pytest.raises(ValidationError):
        Decision(control_id="C-X", threat_ids=[], acton=Action.block)  # type: ignore[call-arg]


def test_invalid_literal_is_rejected():
    with pytest.raises(ValidationError):
        Decision(control_id="C-X", threat_ids=[], action=Action.flag, severity="hihg")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        _ctx(profile="lenient")


def test_context_is_frozen_and_copyable():
    ctx = _ctx()
    with pytest.raises(ValidationError):
        ctx.risk = 0.9  # type: ignore[misc]
    later = ctx.model_copy(update={"stage": Stage.output, "risk": 0.4})
    assert later.stage == Stage.output and later.risk == 0.4 and ctx.risk == 0.0


def test_raw_text_not_in_repr():
    seg = Segment(idx=0, text="AKIAIOSFODNN7EXAMPLE", norm="akiaiosfodnn7example", origin=Origin.user)
    assert "AKIA" not in repr(seg)
    assert "AKIA" not in repr(_ctx(segments=[seg]))


def test_audit_decision_drops_offsets_and_internal_fields():
    d = Decision(
        control_id="C-SECRET-OUT",
        threat_ids=["TH-04"],
        action=Action.redact,
        matches=[Match(kind="aws_access_key", segment_idx=3, start=10, end=30, masked="AKIA****")],
        risk=0.9,
        taints_session=True,
    )
    dumped = AuditDecision.from_decision(d).model_dump()
    assert dumped["matches"] == [{"kind": "aws_access_key", "segment_idx": 3, "masked": "AKIA****"}]
    assert "risk" not in dumped and "taints_session" not in dumped

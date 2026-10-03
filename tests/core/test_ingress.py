"""Tests for R1 ingress controls: C-MODEL-ALLOW and C-SIZE (§6.3, §7)."""

import pytest

from aicl.controls.ingress import ModelAllowlist, SizeLimits
from aicl.models import Action, RequestContext, Stage
from aicl.normalize import build_segment
from aicl.policy.loader import load_policy_file
from aicl.policy.schema import ControlLevelConfig


@pytest.fixture
def policy(tmp_path):
    # Using default policy
    from pathlib import Path

    repo = Path(__file__).parents[2]
    return load_policy_file(
        repo / "policies" / "default.yaml",
        env={
            "AICL_KEY_SUPPORT": "k-support",
            "AICL_KEY_RESEARCH": "k-research",
            "AICL_KEY_ADMIN": "k-admin",
            "AICL_UPSTREAM_MOCK_URL": "http://mock",
        },
    )


def _ctx(model="mock-commercial", role="support_agent", segments=None, artifact=None):
    if segments is None:
        segments = [build_segment(0, "hello", "user")]
    return RequestContext(
        request_id="req-test",
        session_id="sess-test",
        endpoint="chat",
        stage=Stage.ingress,
        identity="support-agent-01",
        role=role,
        profile="balanced",
        model=model,
        segments=segments,
        artifact=artifact,
        policy_version="test-v1",
    )


# --- C-MODEL-ALLOW tests ---------------------------------------------------


@pytest.mark.asyncio
async def test_model_allow_permitted(policy):
    ctrl = ModelAllowlist()
    cfg = policy.level_config("C-MODEL-ALLOW", "balanced")
    assert cfg is not None

    # support_agent has [mock-commercial, ollama-local]
    ctx = _ctx(model="mock-commercial", role="support_agent")
    dec = await ctrl.evaluate(ctx, cfg)
    assert dec.action == Action.allow

    ctx2 = _ctx(model="ollama-local", role="support_agent")
    dec2 = await ctrl.evaluate(ctx2, cfg)
    assert dec2.action == Action.allow


@pytest.mark.asyncio
async def test_model_allow_disallowed_for_role(policy):
    ctrl = ModelAllowlist()
    cfg = policy.level_config("C-MODEL-ALLOW", "balanced")

    # researcher has only [ollama-local] -> mock-commercial is disallowed
    ctx = _ctx(model="mock-commercial", role="researcher")
    dec = await ctrl.evaluate(ctx, cfg)
    assert dec.action == Action.block
    assert dec.threat_ids == ["TH-06"]
    assert "mock-commercial" in dec.reason
    assert dec.matches[0].kind == "disallowed_model"


@pytest.mark.asyncio
async def test_model_allow_wildcard_admin(policy):
    ctrl = ModelAllowlist()
    cfg = policy.level_config("C-MODEL-ALLOW", "balanced")

    # admin has ["*"] -> any model defined in policy is allowed
    ctx = _ctx(model="mock-commercial", role="admin")
    dec = await ctrl.evaluate(ctx, cfg)
    assert dec.action == Action.allow


# --- C-SIZE tests ----------------------------------------------------------


@pytest.mark.asyncio
async def test_size_limits_within_bounds(policy):
    ctrl = SizeLimits()
    cfg = policy.level_config("C-SIZE", "balanced")
    ctx = _ctx(segments=[build_segment(0, "normal length message", "user")])
    dec = await ctrl.evaluate(ctx, cfg)
    assert dec.action == Action.allow


@pytest.mark.asyncio
async def test_size_limits_exceed_message_count(policy):
    ctrl = SizeLimits()
    # Default max_messages is 200, test with override cfg
    cfg = ControlLevelConfig(
        control_key="size_limits",
        control_id="C-SIZE",
        threat_ids=["TH-20"],
        action=Action.block,
        mode="enforce",
        on_error="fail_closed",
        max_messages=2,
    )
    segments = [
        build_segment(0, "msg 1", "user"),
        build_segment(1, "msg 2", "assistant"),
        build_segment(2, "msg 3", "user"),
    ]
    ctx = _ctx(segments=segments)
    dec = await ctrl.evaluate(ctx, cfg)
    assert dec.action == Action.block
    assert dec.threat_ids == ["TH-20"]
    assert "message count 3 exceeds limit of 2" in dec.reason


@pytest.mark.asyncio
async def test_size_limits_exceed_chars_per_message(policy):
    ctrl = SizeLimits()
    cfg = ControlLevelConfig(
        control_key="size_limits",
        control_id="C-SIZE",
        threat_ids=["TH-20"],
        action=Action.block,
        mode="enforce",
        on_error="fail_closed",
        max_chars_per_message=10,
    )
    segments = [build_segment(0, "this is way too long for limit 10", "user")]
    ctx = _ctx(segments=segments)
    dec = await ctrl.evaluate(ctx, cfg)
    assert dec.action == Action.block
    assert dec.threat_ids == ["TH-20"]
    assert "length 33 chars exceeds limit of 10" in dec.reason


@pytest.mark.asyncio
async def test_size_limits_leave_body_bytes_to_the_flow(policy):
    # max_body_bytes is enforced while reading the body (see test_gateway), not by the control.
    ctrl = SizeLimits()
    cfg = ControlLevelConfig(
        control_key="size_limits",
        control_id="C-SIZE",
        threat_ids=["TH-20"],
        action=Action.block,
        mode="enforce",
        on_error="fail_closed",
        max_body_bytes=1,
    )
    dec = await ctrl.evaluate(_ctx(segments=[build_segment(0, "some message", "user")]), cfg)
    assert dec.action == Action.allow


@pytest.mark.asyncio
async def test_model_allow_uses_policy_action_and_threats():
    cfg = ControlLevelConfig(
        control_key="model_allowlist",
        control_id="C-MODEL-ALLOW",
        threat_ids=["TH-99"],
        action=Action.flag,
        mode="enforce",
        on_error="fail_closed",
    )
    # Not attached to a policy: role permissions are unknown, so the control fails closed
    # with the configured action and threat ids.
    dec = await ModelAllowlist().evaluate(_ctx(), cfg)
    assert dec.action == Action.flag and dec.threat_ids == ["TH-99"]


@pytest.mark.asyncio
async def test_size_limits_exceed_artifact_bytes(policy):
    ctrl = SizeLimits()
    cfg = ControlLevelConfig(
        control_key="size_limits",
        control_id="C-SIZE",
        threat_ids=["TH-20"],
        action=Action.block,
        mode="enforce",
        on_error="fail_closed",
        max_artifact_bytes=50,
    )
    ctx = _ctx(artifact=b"x" * 100)
    dec = await ctrl.evaluate(ctx, cfg)
    assert dec.action == Action.block
    assert dec.threat_ids == ["TH-20"]
    assert "artifact size 100 bytes exceeds limit of 50" in dec.reason

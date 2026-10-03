"""Engine tests with throwaway controls; no real detectors involved."""

from pathlib import Path

import pytest
import yaml

from aicl.engine import controls_for_stage, missing_controls, run_stage
from aicl.models import Action, Decision, Match, Origin, RequestContext, Stage
from aicl.normalize import build_segment
from aicl.policy.loader import parse_policy

DEFAULT = Path(__file__).parents[2] / "policies" / "default.yaml"


class Fake:
    """Configurable control. `behaviour(ctx, cfg) -> Decision` decides what it returns."""

    def __init__(self, cid, priority=10, stages=(Stage.input,), behaviour=None):
        self.id = cid
        self.priority = priority
        self.stages = stages
        self.behaviour = behaviour or (lambda ctx, cfg: allow(cid))
        self.calls = []

    async def evaluate(self, ctx, cfg):
        self.calls.append((ctx, cfg))
        return self.behaviour(ctx, cfg)


def allow(cid, **kw):
    return Decision(control_id=cid, threat_ids=[], action=Action.allow, **kw)


def act(cid, action, **kw):
    return Decision(control_id=cid, threat_ids=["TH-X"], action=action, **kw)


def control_entry(cid, levels=None, **extra):
    levels = levels or {"strict": "block", "balanced": "block", "permissive": "flag"}
    return {
        "id": cid,
        "threat_ids": ["TH-X"],
        "levels": {p: {"action": a} for p, a in levels.items()},
        **extra,
    }


def policy(controls: dict, **top):
    data = yaml.safe_load(DEFAULT.read_text(encoding="utf-8"))
    data["controls"] = controls
    data.update(top)
    return parse_policy(yaml.safe_dump(data), {})


def ctx(*texts, profile="balanced"):
    return RequestContext(
        request_id="req_1",
        session_id="s1",
        endpoint="chat",
        stage=Stage.input,
        identity="support-agent-01",
        role="support_agent",
        profile=profile,
        model="mock-commercial",
        segments=[build_segment(i, t, Origin.user) for i, t in enumerate(texts)],
        policy_version="v",
    )


async def run(controls, pol, c=None, stage=Stage.input):
    return await run_stage(pol, c or ctx("hello"), stage, {f.id: f for f in controls})


# --- selection ----------------------------------------------------------------------------------


async def test_all_allow():
    a, b = Fake("C-A"), Fake("C-B")
    res = await run([a, b], policy({"a": control_entry("C-A"), "b": control_entry("C-B")}))
    assert res.action == Action.allow and not res.stopped
    assert [d.control_id for d in res.decisions] == ["C-A", "C-B"]
    assert all(d.latency_ms >= 0 for d in res.decisions)
    assert res.blocking is None and res.errors == []


async def test_priority_order_and_stage_filter():
    order = []

    def rec(cid):
        return lambda ctx, cfg: order.append(cid) or allow(cid)

    controls = [
        Fake("C-LATE", priority=500, behaviour=rec("C-LATE")),
        Fake("C-EARLY", priority=1, behaviour=rec("C-EARLY")),
        Fake("C-OUT", stages=(Stage.output,), behaviour=rec("C-OUT")),
    ]
    pol = policy({k: control_entry(k) for k in ("C-LATE", "C-EARLY", "C-OUT")})
    await run(controls, pol)
    assert order == ["C-EARLY", "C-LATE"]


async def test_disabled_unknown_and_stage_override():
    a, b, c = Fake("C-A"), Fake("C-B"), Fake("C-C", stages=(Stage.output,))
    pol = policy(
        {
            "a": control_entry("C-A", enabled=False),
            "c": control_entry("C-C", stages=["input"]),  # policy moves C-C to input
            "ghost": control_entry("C-GHOST"),
        }
    )
    selected = [cid for _, cid in controls_for_stage(pol, Stage.input, {x.id: x for x in (a, b, c)})]
    assert selected == ["C-C"]  # C-A disabled, C-B not in policy (= disabled)
    assert missing_controls(pol, {x.id: x for x in (a, b, c)}) == ["C-GHOST"]


async def test_profile_selects_level_config():
    f = Fake("C-A", behaviour=lambda ctx, cfg: act("C-A", cfg.action))
    pol = policy({"a": control_entry("C-A")})
    assert (await run([f], pol, ctx("x", profile="strict"))).action == Action.block
    assert (await run([f], pol, ctx("x", profile="permissive"))).action == Action.flag


# --- merging ------------------------------------------------------------------------------------


async def test_precedence_with_collect_all():
    controls = [
        Fake("C-FLAG", 1, behaviour=lambda c, g: act("C-FLAG", Action.flag)),
        Fake("C-BLOCK", 2, behaviour=lambda c, g: act("C-BLOCK", Action.block)),
        Fake("C-APPR", 3, behaviour=lambda c, g: act("C-APPR", Action.require_approval)),
    ]
    pol = policy({f.id: control_entry(f.id) for f in controls}, evaluation="collect_all")
    res = await run(controls, pol)
    assert res.action == Action.block and res.stopped
    assert res.blocking.control_id == "C-BLOCK"
    assert len(res.decisions) == 3


async def test_first_block_stops_early():
    late = Fake("C-LATE", 9)
    controls = [Fake("C-BLOCK", 1, behaviour=lambda c, g: act("C-BLOCK", Action.block)), late]
    res = await run(controls, policy({f.id: control_entry(f.id) for f in controls}))
    assert res.action == Action.block and late.calls == []


async def test_global_shadow_mode():
    late = Fake("C-LATE", 9)
    controls = [Fake("C-BLOCK", 1, behaviour=lambda c, g: act("C-BLOCK", Action.block)), late]
    res = await run(controls, policy({f.id: control_entry(f.id) for f in controls}, mode="shadow"))
    assert res.action == Action.allow and res.would_have_action == Action.block
    assert res.decisions[0].shadow_suppressed
    assert len(late.calls) == 1  # suppressed block does not stop evaluation


async def test_per_control_shadow_only_affects_that_control():
    controls = [
        Fake("C-SH", 1, behaviour=lambda c, g: act("C-SH", Action.block)),
        Fake("C-EN", 2, behaviour=lambda c, g: act("C-EN", Action.flag)),
    ]
    pol = policy({"sh": control_entry("C-SH", mode="shadow"), "en": control_entry("C-EN")})
    res = await run(controls, pol)
    assert res.action == Action.flag and res.would_have_action == Action.block


async def test_skipped_decision_does_not_count():
    f = Fake("C-SEM", behaviour=lambda c, g: act("C-SEM", Action.block, skipped=True))
    res = await run([f], policy({"s": control_entry("C-SEM")}))
    assert res.action == Action.allow and res.would_have_action is None


# --- errors -------------------------------------------------------------------------------------


def boom(ctx, cfg):
    raise RuntimeError("secret AKIA... in message")


async def test_fail_closed():
    res = await run(
        [Fake("C-A", behaviour=boom)], policy({"a": control_entry("C-A", on_error="fail_closed")})
    )
    assert res.action == Action.block
    assert res.errors == ["C-A: RuntimeError"]
    assert "AKIA" not in res.decisions[0].reason


async def test_fail_open():
    res = await run([Fake("C-A", behaviour=boom)], policy({"a": control_entry("C-A", on_error="fail_open")}))
    assert res.action == Action.allow and res.decisions[0].skipped
    assert res.errors == ["C-A: RuntimeError"]


async def test_on_error_default_and_bad_return_type():
    f = Fake("C-A", behaviour=lambda c, g: {"action": "allow"})
    res = await run([f], policy({"a": control_entry("C-A")}, on_error_default="fail_closed"))
    assert res.action == Action.block and res.errors == ["C-A: TypeError"]


# --- risk and taint -----------------------------------------------------------------------------


async def test_risk_is_running_max_visible_to_later_controls():
    seen = []
    controls = [
        Fake("C-PAT", 1, behaviour=lambda c, g: allow("C-PAT", risk=0.6)),
        Fake("C-LOW", 2, behaviour=lambda c, g: allow("C-LOW", risk=0.2)),
        Fake("C-SEM", 500, behaviour=lambda c, g: seen.append(c.risk) or allow("C-SEM")),
    ]
    res = await run(controls, policy({f.id: control_entry(f.id) for f in controls}))
    assert seen == [0.6] and res.risk == 0.6


async def test_taint_only_from_effective_decisions():
    t = Fake("C-T", behaviour=lambda c, g: allow("C-T", taints_session=True))
    assert (await run([t], policy({"t": control_entry("C-T")}))).taints_session
    shadowed = Fake("C-T", behaviour=lambda c, g: act("C-T", Action.flag, taints_session=True))
    res = await run([shadowed], policy({"t": control_entry("C-T", mode="shadow")}))
    assert not res.taints_session


# --- redaction ----------------------------------------------------------------------------------


def m(kind, idx, start, end, **kw):
    return Match(kind=kind, segment_idx=idx, start=start, end=end, masked="***", **kw)


async def test_redaction_replaces_and_merges_spans():
    text = "mail jan@example.com tel 600100200 end"
    controls = [
        Fake("C-PII", 1, behaviour=lambda c, g: act("C-PII", Action.redact, matches=[m("email", 1, 5, 20)])),
        Fake(
            "C-PII2",
            2,
            behaviour=lambda c, g: act(
                "C-PII2", Action.redact, matches=[m("phone", 1, 25, 34), m("email_part", 1, 10, 22)]
            ),
        ),
    ]
    c = ctx("untouched", text)
    res = await run(controls, policy({f.id: control_entry(f.id) for f in controls}), c)
    assert res.action == Action.redact
    assert res.segments[0] is c.segments[0]
    assert res.segments[1].text == "mail [REDACTED:email]el [REDACTED:phone] end"
    assert res.segments[1].norm == "mail [redacted:email]el [redacted:phone] end"
    assert c.segments[1].text == text  # original context unchanged


async def test_flag_matches_are_not_redacted():
    controls = [
        Fake("C-R", 1, behaviour=lambda c, g: act("C-R", Action.redact, matches=[m("email", 0, 0, 4)])),
        Fake("C-F", 2, behaviour=lambda c, g: act("C-F", Action.flag, matches=[m("ip", 0, 5, 9)])),
    ]
    res = await run(controls, policy({f.id: control_entry(f.id) for f in controls}), ctx("abcd efgh"))
    assert res.segments[0].text == "[REDACTED:email] efgh"


@pytest.mark.parametrize(
    "match",
    [
        Match(kind="aws_access_key", segment_idx=0, masked="AKIA****", in_decoded=True),
        Match(kind="email", segment_idx=0, start=0, end=999),  # out of bounds
        Match(kind="email", segment_idx=7, start=0, end=2),  # unknown segment
        None,  # redact with no matches at all
    ],
)
async def test_unredactable_match_escalates_to_block(match):
    matches = [match] if match else []
    f = Fake("C-SEC", behaviour=lambda c, g: act("C-SEC", Action.redact, matches=matches))
    res = await run([f], policy({"s": control_entry("C-SEC")}), ctx("some text"))
    assert res.action == Action.block and res.blocking.control_id == "C-SEC"
    assert res.segments[0].text == "some text"


async def test_audit_view_has_no_offsets():
    f = Fake("C-R", behaviour=lambda c, g: act("C-R", Action.redact, matches=[m("email", 0, 0, 4)]))
    res = await run([f], policy({"r": control_entry("C-R")}), ctx("abcd"))
    dumped = res.audit_decisions()[0].model_dump()
    assert "start" not in dumped["matches"][0]
    assert set(res.latency_per_control()) == {"C-R"}

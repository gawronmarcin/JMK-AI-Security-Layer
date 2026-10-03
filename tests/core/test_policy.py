from pathlib import Path

import pytest
import yaml

from aicl.models import Action
from aicl.policy.loader import PolicyError, load_policy_file, parse_policy

DEFAULT = Path(__file__).parents[2] / "policies" / "default.yaml"
ENV = {"AICL_KEY_SUPPORT": "k-support", "AICL_KEY_RESEARCH": "k-research", "AICL_KEY_ADMIN": "k-admin"}


def _mutated(fn) -> str:
    data = yaml.safe_load(DEFAULT.read_text(encoding="utf-8"))
    fn(data)
    return yaml.safe_dump(data)


def test_default_policy_is_valid():
    p = load_policy_file(DEFAULT, ENV)
    assert len(p.version) == 12
    assert p.warnings == ()
    assert p.identity_for_key("k-support").id == "support-agent-01"
    assert p.identity_for_key("nope") is None


def test_profiles_and_level_config():
    p = load_policy_file(DEFAULT, ENV)
    research = p.identities["research-agent-01"]
    admin = p.identities["admin"]
    assert p.profile_for(research) == "strict"
    assert p.profile_for(admin) == "balanced"  # falls back to active_profile

    cfg = p.level_config("C-INJ-SEM", "permissive")
    assert cfg.action == Action.flag and cfg.threshold == 0.85
    assert cfg.on_error == "fail_open" and cfg.mode == "enforce"
    assert cfg.threat_ids == ["TH-01", "TH-02"]

    pii = p.level_config("C-PII-OUT", "balanced")
    assert pii.action == Action.redact and "email" in pii.types  # params merged in
    assert pii.policy is p
    assert pii.get("missing", 7) == 7


def test_role_helpers():
    p = load_policy_file(DEFAULT, ENV)
    assert p.role_allows_model("support_agent", "mock-commercial")
    assert not p.role_allows_model("researcher", "mock-commercial")
    assert p.role_allows_model("admin", "ollama-local")
    assert not p.role_allows_model("admin", "anything")  # "*" = any model defined in the policy
    assert p.role_allows_tool("support_agent", "send_email")
    assert not p.role_allows_tool("support_agent", "run_shell")
    assert p.budget_for("researcher").max_cost_usd is None


def test_disabled_control_has_no_level_config():
    src = _mutated(lambda d: d["controls"]["pii_output"].update(enabled=False))
    p = parse_policy(src, ENV)
    assert p.level_config("C-PII-OUT", "balanced") is None
    assert p.control_spec("C-PII-OUT") is not None


def test_version_changes_with_content():
    a = parse_policy(DEFAULT.read_text(encoding="utf-8"), ENV)
    b = parse_policy(_mutated(lambda d: d.update(active_profile="strict")), ENV)
    assert a.version != b.version


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d["controls"]["pii_output"].update(enabeld=False), "controls.pii_output.enabeld"),
        (
            lambda d: d["controls"]["pii_output"]["levels"]["strict"].update(action="blok"),
            "levels.strict.action",
        ),
        (lambda d: d["controls"]["pii_output"]["levels"].pop("permissive"), "missing: permissive"),
        (lambda d: d.update(active_profile="lenient"), "active_profile"),
        (lambda d: d["identities"][0].update(role="ghost"), "unknown role 'ghost'"),
        (lambda d: d["roles"]["researcher"]["models"].append("gpt-9"), "unknown model 'gpt-9'"),
        (lambda d: d["roles"]["researcher"].update(budget="nope"), "unknown budget 'nope'"),
        (lambda d: d["controls"]["canary"].update(id="C-PII-OUT"), "duplicate 'C-PII-OUT'"),
        (lambda d: d["controls"]["pii_output"]["params"].update(action="x"), "reserved names"),
        (lambda d: d.update(version=2), "version"),
    ],
)
def test_invalid_policies_are_rejected_with_readable_errors(mutate, expected):
    with pytest.raises(PolicyError) as exc:
        parse_policy(_mutated(mutate), ENV)
    assert expected in str(exc.value)


def test_yaml_syntax_error():
    with pytest.raises(PolicyError, match="YAML syntax"):
        parse_policy("version: 1\ncontrols: [unclosed", ENV)


def test_missing_key_env_is_a_warning_not_an_error():
    p = parse_policy(DEFAULT.read_text(encoding="utf-8"), {"AICL_KEY_ADMIN": "k-admin"})
    assert len(p.warnings) == 2
    assert p.identity_for_key("k-admin").id == "admin"


def test_shared_api_key_is_rejected():
    with pytest.raises(PolicyError, match="share the same API key"):
        parse_policy(DEFAULT.read_text(encoding="utf-8"), ENV | {"AICL_KEY_ADMIN": "k-support"})


def test_cfg_get_returns_envelope_fields_and_params():
    cfg = load_policy_file(DEFAULT, ENV).level_config("C-INJ-SEM", "permissive")
    assert cfg.get("action") == Action.flag
    assert cfg.get("threat_ids") == ["TH-01", "TH-02"]
    assert cfg.get("threshold") == 0.85
    assert cfg.get("missing", "default") == "default"


def test_compiled_level_config_is_immutable():
    from pydantic import ValidationError

    cfg = load_policy_file(DEFAULT, ENV).level_config("C-PII-OUT", "balanced")
    with pytest.raises(ValidationError):
        cfg.action = Action.allow
    with pytest.raises(ValidationError):
        cfg.types = []


def test_unattached_cfg_policy_raises_attribute_error():
    from aicl.policy.schema import ControlLevelConfig

    cfg = ControlLevelConfig(
        control_key="k",
        control_id="C-X",
        threat_ids=[],
        action=Action.block,
        mode="enforce",
        on_error="fail_closed",
    )
    assert getattr(cfg, "policy", None) is None

"""catalog/threats.yaml: well-formed, and every threat id used by the policy is defined."""

import re
from pathlib import Path

import yaml

REPO = Path(__file__).parents[2]
FORMATS = {
    "owasp_llm": re.compile(r"LLM(0[1-9]|10):2025"),
    "owasp_agentic": re.compile(r"ASI(0[1-9]|10)"),
    "atlas": re.compile(r"AML\.T\d{4}(\.\d{3})?"),
}


def _threats():
    return yaml.safe_load((REPO / "catalog" / "threats.yaml").read_text(encoding="utf-8"))["threats"]


def test_catalog_entries_are_well_formed():
    threats = _threats()
    ids = [t["id"] for t in threats]
    assert len(ids) == len(set(ids))
    for t in threats:
        assert re.fullmatch(r"TH-\d{2}", t["id"])
        assert t["name"] and t["description"]
        for key, rx in FORMATS.items():
            assert isinstance(t[key], list), f"{t['id']}.{key} must be a list"
            bad = [v for v in t[key] if not rx.fullmatch(v)]
            assert not bad, f"{t['id']}.{key}: {bad}"


def test_policy_threat_ids_exist_in_catalog():
    ids = {t["id"] for t in _threats()}
    policy = yaml.safe_load((REPO / "policies" / "default.yaml").read_text(encoding="utf-8"))
    used = {tid for c in policy["controls"].values() for tid in c.get("threat_ids", [])}
    assert used <= ids, sorted(used - ids)

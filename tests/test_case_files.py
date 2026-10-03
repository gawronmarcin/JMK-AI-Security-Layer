"""Walidacja plików przypadków i wymagań pokrycia (§11.5) — BEZ gatewaya.
Dzięki temu literówka w YAML jest wykrywana w sekundę, w CI, zanim ktoś odpali pełny suite."""

from __future__ import annotations

import os
import warnings
from collections import Counter
from pathlib import Path

import pytest
import yaml

from tests.harness.case_schema import CaseSpec, load_all_cases
from tests.payloads.artifacts import GENERATORS

CASES = load_all_cases(Path(__file__).parent / "cases")
P0 = ["C-AUTH", "C-MODEL-ALLOW", "C-SIZE", "C-INJ-PAT", "C-PII-IN", "C-PII-OUT", "C-SECRET-IN",
      "C-SECRET-OUT", "C-TOOL-ACL", "C-CODE-EXEC", "C-ARTIFACT", "C-SIG", "C-BUDGET", "C-LOOP"]


def test_cases_loaded():
    assert CASES, "brak przypadków w tests/cases"


def test_artifact_generators_exist():
    for c in CASES:
        for s in c.steps:
            if s.request.artifact:
                assert s.request.artifact.generator in GENERATORS, c.id


def test_threat_ids_known():
    catalog = Path(__file__).resolve().parents[1] / "catalog" / "threats.yaml"
    if not catalog.exists():
        pytest.skip("catalog/threats.yaml jeszcze nie istnieje (R6)")
    data = yaml.safe_load(catalog.read_text()) or {}
    known = {t["id"] for t in (data.get("threats", data) if isinstance(data, dict) else data)}
    unknown = {t for c in CASES for t in c.threats} - known
    assert not unknown, f"threat_ids spoza katalogu: {sorted(unknown)}"


def test_typo_in_case_is_rejected():
    with pytest.raises(Exception):
        CaseSpec.model_validate({"id": "X", "title": "t", "kind": "negative", "controls": ["C"],
                                 "steps": [{"request": {"endpoint": "chat"}, "expcet": {}}]})


def test_minimum_coverage_per_p0_control():
    """§11.5: ≥3 neg, ≥3 pos, ≥2 edge per kontrola P0. Domyślnie ostrzeżenie (w trakcie
    hackathonu kontrole dochodzą), twardy błąd z AICL_TEST_STRICT_COVERAGE=1."""
    counts = {cid: Counter() for cid in P0}
    for c in CASES:
        for cid in c.controls:
            if cid in counts:
                counts[cid][c.kind] += 1
    gaps = {cid: dict(cnt) for cid, cnt in counts.items()
            if cnt["negative"] < 3 or cnt["positive"] < 3 or cnt["edge"] < 2}
    if gaps:
        msg = "braki pokrycia 3/3/2: " + ", ".join(f"{k}={v}" for k, v in gaps.items())
        if os.environ.get("AICL_TEST_STRICT_COVERAGE") == "1":
            pytest.fail(msg)
        warnings.warn(msg)

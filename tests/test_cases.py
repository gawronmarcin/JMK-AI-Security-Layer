"""Sparametryzowany runner nad tests/cases/*.yaml (§11.3).

Jeden przypadek YAML = jeden test pytest o id `<plik>::<case.id>`, np.
    pytest -k INJ-001          # pojedynczy przypadek
    pytest -k "pii and not edge"
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.harness import report
from tests.harness.case_schema import load_all_cases
from tests.harness.runner import run_case

CASES_DIR = Path(__file__).parent / "cases"
CASES = load_all_cases(CASES_DIR)   # błąd schematu = błąd zbierania testów (głośno)


def _param(case):
    marks = [pytest.mark.gateway]
    if "live" in case.tags:
        marks.append(pytest.mark.live)
    return pytest.param(case, id=f"{case.source}::{case.id}", marks=marks)


@pytest.mark.parametrize("case", [_param(c) for c in CASES])
async def test_case(case, gateway):
    async with gateway(overlay=case.policy_overlay, profile=case.profile,
                       identity=case.identity) as gw:
        outcome = await run_case(gw, case)
    report.RESULTS.append(outcome)
    if case.xfail and not outcome.passed:
        pytest.xfail(case.xfail)
    assert outcome.passed, f"{case.id} — {case.title}\n  " + "\n  ".join(outcome.failures)

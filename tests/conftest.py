"""Wspólne fixture'y i hooki pytest dla całego środowiska testowego AICL.

  mocks            — (session) mock LLM + mock narzędzi na losowych portach 127.0.0.1
  gateway          — fabryka: `async with gateway(overlay=..., profile=...) as gw:`
  gateway_required — pomija test, jeśli gateway (aicl.app) jeszcze nie istnieje

Hooki: zbieranie wyników przypadków YAML -> reports/test_report.{json,md}
oraz tabelka podsumowania na końcu `make test` (§11.8).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.harness import report
from tests.harness.gateway import Mocks, load_factory, running_gateway
from tests.mocks import mock_llm, mock_tools
from tests.mocks.server import BackgroundServer

REPORTS_DIR = Path(os.environ.get("AICL_REPORTS_DIR", Path(__file__).resolve().parents[1] / "reports"))


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--live", action="store_true", default=False,
                     help="uruchom też testy wymagające prawdziwego Ollamy (marker live)")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: wymaga prawdziwego Ollamy (domyślnie pomijane)")
    config.addinivalue_line("markers", "perf: pomiar wydajności (zapisuje reports/perf.json)")
    config.addinivalue_line("markers", "gateway: wymaga działającego gatewaya aicl")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--live") or os.environ.get("AICL_LIVE") == "1":
        return
    skip_live = pytest.mark.skip(reason="live: uruchom z --live / make test-live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip_live)


# ------------------------------------------------------------------ dostępność gatewaya
def _gateway_import_error() -> str | None:
    try:
        load_factory()
        return None
    except Exception as e:  # ImportError, AttributeError...
        return f"{type(e).__name__}: {e}"


@pytest.fixture(scope="session")
def gateway_required() -> None:
    err = _gateway_import_error()
    if err:
        msg = (f"gateway niedostępny ({err}). Ustaw AICL_APP_FACTORY albo poczekaj na R1. "
               f"Inną implementację wskaż przez AICL_APP_FACTORY=modul:fabryka")
        if os.environ.get("AICL_TEST_REQUIRE_GATEWAY") == "1":   # w CI: twardy błąd
            pytest.fail(msg)
        pytest.skip(msg)


# ------------------------------------------------------------------ mocki
@pytest.fixture(scope="session")
def mocks():
    with BackgroundServer(mock_llm.app) as llm, BackgroundServer(mock_tools.app) as tools:
        yield Mocks(llm_url=llm.url, tools_url=tools.url)


@pytest.fixture
def gateway(mocks, tmp_path, gateway_required):
    """Fabryka gatewaya: każdy `async with` = świeża aplikacja i własna polityka."""
    counter = {"n": 0}

    def _make(overlay: dict | None = None, profile: str | None = None,
              identity: str | None = None, extra_env: dict | None = None):
        counter["n"] += 1
        return running_gateway(mocks, tmp_path / f"gw{counter['n']}", overlay=overlay,
                               profile=profile, identity=identity, extra_env=extra_env)
    return _make


# ------------------------------------------------------------------ raport
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if report.RESULTS:
        session.config._aicl_summary = report.write(report.RESULTS, REPORTS_DIR)  # type: ignore[attr-defined]


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    s = getattr(config, "_aicl_summary", None)
    if s:
        terminalreporter.section("AICL summary")
        for row in report.terminal_table(s):
            terminalreporter.write_line(row)
        terminalreporter.write_line(f"raport: {REPORTS_DIR / 'test_report.md'}")

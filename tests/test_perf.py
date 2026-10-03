"""§12: narzut deterministycznego pipeline'u, cel p95 < ~20 ms dla ~2 KB promptu.
To POMIAR, nie założenie: wynik zawsze trafia do reports/perf.json; asercja tylko
gdy AICL_PERF_STRICT=1 (laptop jury != CI)."""

from __future__ import annotations

import json
import os
import statistics
import time
from pathlib import Path

import pytest

from tests.harness.report import pct

pytestmark = [pytest.mark.gateway, pytest.mark.perf]

N = int(os.environ.get("AICL_PERF_N", "200"))
TARGET_P95_MS = float(os.environ.get("AICL_PERF_P95_MS", "20"))
PROMPT = ("Please summarise the attached maintenance log for the support team. " * 30)[:2048]


# N requests from one identity would hit max_requests_per_minute (C-BUDGET -> 429):
# this test measures overhead, not budgets, so the limit is lifted (null = removed).
NO_RATE_LIMIT = {"budgets": {"support_default": {"max_requests_per_minute": None}}}


async def test_overhead_p95(gateway):
    async with gateway(profile="balanced", overlay=NO_RATE_LIMIT) as gw:
        h = {**gw.auth("support-agent-01"), "X-Mock-Scenario": "fixed:ok"}
        body = {"model": "mock-commercial", "messages": [{"role": "user", "content": PROMPT}]}
        for _ in range(10):   # rozgrzewka (importy, regexy, pool połączeń)
            await gw.client.post("/v1/chat/completions", json=body, headers=h)
        overhead, wall = [], []
        for _ in range(N):
            t0 = time.perf_counter()
            r = await gw.client.post("/v1/chat/completions", json=body, headers=h)
            wall.append((time.perf_counter() - t0) * 1000)
            assert r.status_code == 200, r.text
            if r.headers.get("x-aicl-overhead-ms"):
                overhead.append(float(r.headers["x-aicl-overhead-ms"]))
    result = {"n": N, "prompt_bytes": len(PROMPT.encode()),
              "overhead_ms": {"p50": pct(overhead, 50), "p95": pct(overhead, 95), "p99": pct(overhead, 99),
                              "mean": round(statistics.mean(overhead), 3) if overhead else None},
              "wall_ms_incl_mock_upstream": {"p50": pct(wall, 50), "p95": pct(wall, 95)},
              "target_p95_ms": TARGET_P95_MS}
    out = Path(os.environ.get("AICL_REPORTS_DIR", Path(__file__).resolve().parents[1] / "reports"))
    out.mkdir(exist_ok=True)
    (out / "perf.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result))
    assert overhead, "gateway nie zwraca X-AICL-Overhead-Ms (§5.1)"
    if os.environ.get("AICL_PERF_STRICT") == "1":
        assert result["overhead_ms"]["p95"] <= TARGET_P95_MS

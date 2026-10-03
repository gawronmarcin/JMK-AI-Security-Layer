"""Metryki i raport (§11.6): detection rate, false-positive rate, latencje, macierz pokrycia.

Definicje:
  detection rate (DR)  = negatywne zatrzymane / negatywne         (wyższe = lepiej)
  false-positive (FPR) = pozytywne zatrzymane / pozytywne         (niższe = lepiej)
  "zatrzymane" = block | require_approval | redact albo status 401/403/429
  edge = liczone tylko jako pass/fail (oczekiwanie zależy od przypadku)
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from tests.harness.runner import CaseOutcome

RESULTS: list[CaseOutcome] = []


def pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = max(0, min(len(v) - 1, round(q / 100 * (len(v) - 1))))
    return round(v[k], 3)


def summarize(results: list[CaseOutcome]) -> dict[str, Any]:
    per: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "negative": 0, "negative_stopped": 0, "positive": 0, "positive_stopped": 0,
        "edge": 0, "passed": 0, "failed": 0, "latency": [], "threats": set(), "cases": []})
    overhead: list[float] = []
    for r in results:
        for s in r.steps:
            if s.overhead_ms is not None:
                overhead.append(s.overhead_ms)
        for cid in r.case.controls:
            p = per[cid]
            p[r.case.kind] += 1
            if r.case.kind == "negative" and r.stopped:
                p["negative_stopped"] += 1
            if r.case.kind == "positive" and r.stopped:
                p["positive_stopped"] += 1
            p["passed" if r.passed else "failed"] += 1
            p["threats"].update(r.case.threats)
            p["cases"].append(r.case.id)
            for s in r.steps:
                if cid in s.per_control_ms:
                    p["latency"].append(float(s.per_control_ms[cid]))

    controls = {}
    for cid, p in sorted(per.items()):
        controls[cid] = {
            "negative": p["negative"], "positive": p["positive"], "edge": p["edge"],
            "passed": p["passed"], "failed": p["failed"],
            "detection_rate": round(p["negative_stopped"] / p["negative"], 3) if p["negative"] else None,
            "false_positive_rate": round(p["positive_stopped"] / p["positive"], 3) if p["positive"] else None,
            "latency_ms_p50": pct(p["latency"], 50), "latency_ms_p95": pct(p["latency"], 95),
            "threats": sorted(p["threats"]), "cases": p["cases"],
            "meets_min_coverage": p["negative"] >= 3 and p["positive"] >= 3 and p["edge"] >= 2,
        }
    neg = [r for r in results if r.case.kind == "negative"]
    pos = [r for r in results if r.case.kind == "positive"]
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "totals": {
            "cases": len(results), "passed": sum(r.passed for r in results),
            "failed": sum(not r.passed for r in results),
            "detection_rate": round(sum(r.stopped for r in neg) / len(neg), 3) if neg else None,
            "false_positive_rate": round(sum(r.stopped for r in pos) / len(pos), 3) if pos else None,
            "overhead_ms_p50": pct(overhead, 50), "overhead_ms_p95": pct(overhead, 95),
        },
        "controls": controls,
        "coverage_matrix": [  # threat -> control -> liczba testów
            {"threat": t, "control": cid, "tests": sum(1 for r in results
                                                        if cid in r.case.controls and t in r.case.threats)}
            for cid, c in controls.items() for t in c["threats"]],
        "failures": [{"id": r.case.id, "source": r.case.source, "failures": r.failures}
                     for r in results if not r.passed],
    }


def _fmt(v: Any) -> str:
    """Odsetek (0..1) -> '93%'."""
    return "—" if v is None else f"{v * 100:.0f}%"


def _ms(v: Any) -> str:
    return "—" if v is None else f"{v:.2f}"


def to_markdown(s: dict[str, Any]) -> str:
    t = s["totals"]
    lines = [
        "# AICL — raport z testów", "",
        f"Wygenerowano: {s['generated_at']}", "",
        f"Przypadki: **{t['cases']}**, zaliczone: **{t['passed']}**, niezaliczone: **{t['failed']}**  ",
        f"Detection rate: **{_fmt(t['detection_rate'])}**, false-positive rate: **{_fmt(t['false_positive_rate'])}**  ",
        f"Narzut gatewaya p50/p95: {t['overhead_ms_p50']} / {t['overhead_ms_p95']} ms", "",
        "| Kontrola | neg | pos | edge | pass | fail | DR | FPR | p50 ms | p95 ms | min. pokrycie 3/3/2 |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for cid, c in s["controls"].items():
        lines.append(f"| {cid} | {c['negative']} | {c['positive']} | {c['edge']} | {c['passed']} | "
                     f"{c['failed']} | {_fmt(c['detection_rate'])} | {_fmt(c['false_positive_rate'])} | "
                     f"{_ms(c['latency_ms_p50'])} | {_ms(c['latency_ms_p95'])} | "
                     f"{'tak' if c['meets_min_coverage'] else 'NIE'} |")
    if s["failures"]:
        lines += ["", "## Niezaliczone", ""]
        for f in s["failures"]:
            lines.append(f"- **{f['id']}** ({f['source']}): " + "; ".join(f["failures"])[:500])
    return "\n".join(lines) + "\n"


def write(results: list[CaseOutcome], out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    s = summarize(results)
    (out_dir / "test_report.json").write_text(json.dumps(s, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "test_report.md").write_text(to_markdown(s), encoding="utf-8")
    return s


def terminal_table(s: dict[str, Any]) -> list[str]:
    t = s["totals"]
    rows = [f"AICL: {t['passed']}/{t['cases']} przypadków OK | DR {_fmt(t['detection_rate'])} | "
            f"FPR {_fmt(t['false_positive_rate'])} | overhead p95 {t['overhead_ms_p95']} ms",
            f"{'kontrola':<16}{'neg':>5}{'pos':>5}{'edge':>6}{'fail':>6}{'DR':>7}{'FPR':>7}{'p95ms':>8}"]
    for cid, c in s["controls"].items():
        rows.append(f"{cid:<16}{c['negative']:>5}{c['positive']:>5}{c['edge']:>6}{c['failed']:>6}"
                    f"{_fmt(c['detection_rate']):>7}{_fmt(c['false_positive_rate']):>7}"
                    f"{_ms(c['latency_ms_p95']):>8}")
    return rows

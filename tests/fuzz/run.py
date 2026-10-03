"""Fuzzer mutacyjny: seedy × strategie -> gateway (evaluation: collect_all) -> bypass rate.

    python -m tests.fuzz.run                       # wszystkie strategie
    python -m tests.fuzz.run --strategies b64 rot13 --export-bypasses
    AICL_APP_FACTORY=tests.stub.stub_gateway:create_app python -m tests.fuzz.run

Bypass = atak przeszedł: status 200 i akcja allow/flag (nic go nie zatrzymało).
Wynik: reports/fuzz_<timestamp>.json; z --export-bypasses także
tests/cases/fuzz_bypasses.yaml (gotowe przypadki regresyjne — przejrzyj przed commitem!).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import yaml

from tests.fuzz.mutate import STRATEGIES
from tests.harness.gateway import Mocks, running_gateway
from tests.mocks import mock_llm, mock_tools
from tests.mocks.server import BackgroundServer

ROOT = Path(__file__).resolve().parents[2]


async def fuzz(strategies: list[str], seed_file: Path, profile: str, rng_seed: int) -> dict:
    seeds = yaml.safe_load(seed_file.read_text(encoding="utf-8"))
    rng = random.Random(rng_seed)
    results = []
    with BackgroundServer(mock_llm.app) as llm, BackgroundServer(mock_tools.app) as tools, \
            tempfile.TemporaryDirectory() as tmp:
        mocks = Mocks(llm.url, tools.url)
        async with running_gateway(mocks, Path(tmp), overlay={"evaluation": "collect_all"},
                                   profile=profile, identity="support-agent-01") as gw:
            headers = {**gw.auth("support-agent-01"), "X-Mock-Scenario": "fixed:ok"}
            for seed in seeds:
                for name in strategies:
                    messages = STRATEGIES[name](seed["text"], seed, rng)
                    if not messages:
                        continue
                    r = await gw.client.post("/v1/chat/completions", headers=headers,
                                             json={"model": "mock-commercial", "messages": messages})
                    action = r.headers.get("x-aicl-action") or ("block" if r.status_code in (403, 429) else None)
                    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
                    cid = (body.get("error") or {}).get("control_id") if isinstance(body, dict) else None
                    results.append({"seed": seed["id"], "strategy": name, "status": r.status_code,
                                    "action": action, "control_id": cid,
                                    "bypass": r.status_code == 200 and action in ("allow", "flag", None),
                                    "messages": messages, "controls": seed.get("controls", []),
                                    "threats": seed.get("threats", [])})
    by_strategy = defaultdict(lambda: [0, 0])
    by_control = defaultdict(lambda: [0, 0])
    for r in results:
        by_strategy[r["strategy"]][0] += r["bypass"]; by_strategy[r["strategy"]][1] += 1
        for c in r["controls"]:
            by_control[c][0] += r["bypass"]; by_control[c][1] += 1
    rate = lambda b, n: round(b / n, 3) if n else None   # noqa: E731
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "profile": profile, "rng_seed": rng_seed,
        "total": len(results), "bypasses": sum(r["bypass"] for r in results),
        "bypass_rate": rate(sum(r["bypass"] for r in results), len(results)),
        "by_strategy": {k: {"bypass": b, "n": n, "rate": rate(b, n)} for k, (b, n) in sorted(by_strategy.items())},
        "by_control": {k: {"bypass": b, "n": n, "rate": rate(b, n)} for k, (b, n) in sorted(by_control.items())},
        "results": results,
    }


def export_bypasses(report: dict, path: Path) -> int:
    cases = []
    for i, r in enumerate(x for x in report["results"] if x["bypass"]):
        cases.append({
            "id": f"FUZZ-{r['seed']}-{r['strategy']}-{i}", "title": f"Fuzz bypass: {r['strategy']} on {r['seed']}",
            "kind": "edge", "controls": r["controls"][:1], "threats": r["threats"], "profile": report["profile"],
            "identity": "support-agent-01", "tags": ["fuzz"],
            "steps": [{"request": {"endpoint": "chat", "body": {"model": "mock-commercial", "messages": r["messages"]}},
                       "expect": {"status": 403}}]})
    path.write_text(yaml.safe_dump(cases, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return len(cases)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strategies", nargs="*", default=list(STRATEGIES))
    ap.add_argument("--seeds", type=Path, default=ROOT / "tests" / "cases" / "attacks_seed.yaml")
    ap.add_argument("--profile", default="balanced")
    ap.add_argument("--rng-seed", type=int, default=1337)
    ap.add_argument("--export-bypasses", action="store_true")
    a = ap.parse_args()
    report = asyncio.run(fuzz(a.strategies, a.seeds, a.profile, a.rng_seed))
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    path = out / f"fuzz_{time.strftime('%Y%m%d_%H%M%S')}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"bypass rate: {report['bypass_rate']}  ({report['bypasses']}/{report['total']})  -> {path}")
    for k, v in report["by_strategy"].items():
        print(f"  {k:<18} {v['bypass']:>3}/{v['n']:<3}  {v['rate']}")
    if a.export_bypasses:
        n = export_bypasses(report, ROOT / "tests" / "cases" / "fuzz_bypasses.yaml")
        print(f"wyeksportowano {n} przypadków -> tests/cases/fuzz_bypasses.yaml (status: edge, PRZEJRZYJ)")


if __name__ == "__main__":
    main()

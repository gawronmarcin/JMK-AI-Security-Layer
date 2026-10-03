#!/usr/bin/env python3
"""Regenerates the deterministic DEMO DATA fixtures in aicl/dashboard/demo/.

    python tests/dashboard/generate_demo_fixtures.py

Output is byte-identical for the same seed (see fixtures_lib.SEED). Never contains real data.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures_lib as fx  # noqa: E402

OUT = Path(__file__).resolve().parents[2] / "aicl" / "dashboard" / "demo"


def dump(name, payload):
    (OUT / name).write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    events = fx.generate_events()
    now = fx.ANCHOR
    with (OUT / "audit.sample.jsonl").open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n")
    dump("healthz.json", fx.health_payload())
    dump("summary.json", fx.summary(events, now))
    dump("latency.json", fx.latency(events, now))
    dump("budgets.json", fx.budgets(events, now))
    dump("controls.json", fx.controls_payload())
    dump("policy.json", fx.policy_payload(now))
    dump("test_report.json", fx.test_report(now))
    dump("fuzz_report.json", fx.fuzz_report(now))
    dump("manifest.json", {"anchor": fx.iso(now), "seed": fx.SEED, "events": len(events),
                           "note": "DEMO DATA — deterministic synthetic fixtures, not production telemetry"})
    print(f"wrote {len(events)} events + payloads to {OUT}")


if __name__ == "__main__":
    main()

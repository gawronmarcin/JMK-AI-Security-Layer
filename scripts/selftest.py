"""Live self-test of a RUNNING gateway against the policy it has loaded now (aicl/selftest.py).

    python scripts/selftest.py                                   # gateway on :8080, admin key from env
    python scripts/selftest.py --url http://localhost:8081 --ids inj-direct,pii-in

Edit the policy (e.g. disable a control, switch pii_input to block), wait ~1 s for the hot reload
and run again: the expected outcomes follow the new configuration. Exit code 1 if any probe FAILs.
"""

from __future__ import annotations

import argparse
import os
import sys

import httpx


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("AICL_DEMO_URL", "http://localhost:8080"))
    ap.add_argument("--key", default=os.environ.get("AICL_KEY_ADMIN", "dev-key-admin"), help="admin API key")
    ap.add_argument("--ids", default=None, help="comma-separated probe ids (default: all)")
    args = ap.parse_args()
    params = {"ids": args.ids} if args.ids else None
    r = httpx.post(f"{args.url.rstrip('/')}/admin/selftest/run", params=params,
                   headers={"Authorization": f"Bearer {args.key}"}, timeout=300)
    if r.status_code != 200:
        print(f"self-test failed to run: HTTP {r.status_code} {r.text[:300]}")
        return 2
    rep = r.json()
    print(f"policy {rep['policy_version']}  run {rep['run_id']}\n")
    print(f"{'verdict':7} {'probe':12} {'control':14} {'expected':17} {'actual':17} why")
    for x in rep["results"]:
        exp = x["expected"]["action"] + ("" if x["expected"]["active"] else " (off)") if x["expected"] else "-"
        act = f"{x['action']} {x['status']}" if x["action"] else "-"
        print(f"{x['verdict']:7} {x['id']:12} {x['control']:14} {exp:17} {act:17} {x['note']}")
    s = rep["summary"]
    print(f"\nPASS {s['PASS']}  FAIL {s['FAIL']}  SKIP {s['SKIP']}")
    return 1 if s["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())

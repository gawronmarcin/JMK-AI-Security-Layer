"""Full-stack prompt-injection test against a running gateway (all tiers, real models).

    python scripts/stack_test.py                         # all cases, gateway from AICL_DEMO_URL or :8080
    python scripts/stack_test.py --category encoded      # one category
    python scripts/stack_test.py --lang pl --verbose     # one language, with the decision reason

Prerequisites (docs/SEMANTIC_SETUP.md): mocks on 9001/9002, Ollama with the judge and embedding
models, the gateway started with a policy that enables the detectors (e.g. AICL_POLICY=
policies/local.yaml) and `--env-file .env`. Uses the admin identity (balanced profile, no budget
limits) so the run is not throttled; key from AICL_KEY_ADMIN.

Each case from scripts/stack_cases.yaml is sent through the real API (chat message, tool result
inside a chat, or tool-call arguments), optionally encoded/obfuscated first. Output: one line per
case, detection and false-positive rates per category and language, which control caught what,
latency; full results in reports/stack_test.{json,md}. Synthetic data only.
"""

from __future__ import annotations

import argparse
import base64
import codecs
import json
import os
import sys
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import yaml

REPO = Path(__file__).resolve().parents[1]
CASES = REPO / "scripts" / "stack_cases.yaml"
INJECTION_CONTROLS = {"C-INJ-PAT", "C-INJ-EMB", "C-INJ-BASTION", "C-INJ-SEM"}

_FULLWIDTH = {c: chr(ord(c) + 0xFEE0) for c in map(chr, range(0x21, 0x7F))}
_HOMOGLYPH = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і", "y": "у", "x": "х"})
_LEET = str.maketrans({"o": "0", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7"})


def env_files() -> dict[str, str]:
    env: dict[str, str] = {}
    dotenv = REPO / ".env"
    if dotenv.exists():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    env.update(os.environ)
    return env


def encode(text: str, how: str | None) -> str:
    if not how:
        return text
    if how == "base64":
        return base64.b64encode(text.encode()).decode()
    if how == "hex":
        return text.encode().hex()
    if how == "url":
        return quote(text, safe="")
    if how == "rot13":
        return codecs.encode(text, "rot13")
    if how == "leet":
        return text.translate(_LEET)
    if how == "fullwidth":
        return "".join(_FULLWIDTH.get(c, c) for c in text)
    if how == "zero_width":
        return chr(0x200B).join(text)
    if how == "spaced":
        return " ".join(text)
    if how == "homoglyph":
        return text.translate(_HOMOGLYPH)
    raise ValueError(f"unknown encoding {how!r}")


def build_text(case: dict[str, Any]) -> str:
    payload = encode(case["text"], case.get("encode"))
    text = case.get("wrap", "{payload}").replace("{payload}", payload)
    if case.get("repeat_before"):
        text = case.get("filler", "Lorem ipsum. ") * int(case["repeat_before"]) + text
    return text


def request_for(case: dict[str, Any], text: str) -> tuple[str, dict[str, Any]]:
    channel = case.get("channel", "user")
    if channel == "tool_args":
        return "/v1/tools/invoke", {"tool": "search_docs", "arguments": {"query": text}}
    if channel == "tool_result":
        messages = [
            {"role": "user", "content": "Please summarize the result of the lookup for me."},
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "search_docs", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "call_1", "content": text},
        ]
    else:
        messages = [{"role": "user", "content": text}]
    return "/v1/chat/completions", {"model": "mock-commercial", "messages": messages}


def run_case(client: httpx.Client, case: dict[str, Any], key: str) -> dict[str, Any]:
    text = build_text(case)
    path, body = request_for(case, text)
    headers = {
        "Authorization": f"Bearer {key}",
        "X-AICL-Session": f"stack-{case['id']}-{uuid.uuid4().hex[:6]}",  # fresh session: no taint carry-over
    }
    if path == "/v1/chat/completions":
        # fixed answer from the mock LLM; not for tool calls, where the gateway forwards the header
        # to the tool backend and the canned sentence would become the (untrusted) tool result
        headers["X-Mock-Scenario"] = "fixed:Sure, here is the information you asked for."
    t0 = time.perf_counter()
    try:
        r = client.post(path, json=body, headers=headers)
    except httpx.HTTPError as exc:
        return {"outcome": "error", "detail": f"{type(exc).__name__}", "wall_ms": (time.perf_counter() - t0) * 1000}
    wall = (time.perf_counter() - t0) * 1000
    res: dict[str, Any] = {"status": r.status_code, "wall_ms": wall,
                           "overhead_ms": float(r.headers.get("X-AICL-Overhead-Ms", "nan"))}
    if r.status_code == 403:
        err = (r.json().get("error") or {}) if r.headers.get("content-type", "").startswith("application/json") else {}
        res.update(outcome="block", control=err.get("control_id"), reason=err.get("message") or err.get("reason"))
    elif r.status_code == 200:
        res.update(outcome="allow", action=r.headers.get("X-AICL-Action", "allow"))
    else:
        res.update(outcome="error", detail=r.text[:200])
    return res


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, max(0, round(p / 100 * len(s) + 0.5) - 1))] if s else float("nan")


def verdict(case: dict[str, Any], res: dict[str, Any]) -> str:
    if res["outcome"] == "error":
        return "ERR"
    blocked = res["outcome"] == "block"
    if case["expect"] == "block":
        return "ok" if blocked else "MISS"
    return "FP" if blocked else "ok"


def summarize(rows: list[tuple[dict[str, Any], dict[str, Any], str]]) -> dict[str, Any]:
    def stats(sel):
        att = [v for c, _, v in sel if c["expect"] == "block"]
        ben = [v for c, _, v in sel if c["expect"] == "allow"]
        return {"attacks": len(att), "detected": att.count("ok"), "benign": len(ben),
                "false_positives": ben.count("FP"), "errors": [v for _, _, v in sel].count("ERR")}

    by_cat, by_lang = defaultdict(list), defaultdict(list)
    for row in rows:
        by_cat[row[0]["category"]].append(row)
        by_lang[row[0]["lang"]].append(row)
    caught = Counter(r.get("control") for c, r, _ in rows if r["outcome"] == "block")
    lat_block = [r["wall_ms"] for _, r, _ in rows if r["outcome"] == "block"]
    lat_allow = [r["wall_ms"] for _, r, _ in rows if r["outcome"] == "allow"]
    return {
        "total": stats(rows),
        "by_category": {k: stats(v) for k, v in sorted(by_cat.items())},
        "by_language": {k: stats(v) for k, v in sorted(by_lang.items())},
        "caught_by": dict(caught.most_common()),
        "latency_ms": {
            "blocked_p50": pct(lat_block, 50), "blocked_p95": pct(lat_block, 95),
            "allowed_p50": pct(lat_allow, 50), "allowed_p95": pct(lat_allow, 95),
        },
    }


def rate(s: dict[str, Any]) -> str:
    dr = f"{s['detected']}/{s['attacks']}" if s["attacks"] else "-"
    fp = f"{s['false_positives']}/{s['benign']}" if s["benign"] else "-"
    return f"detected {dr:>7}  false positives {fp:>5}" + (f"  errors {s['errors']}" if s["errors"] else "")


def write_reports(rows, summary, detectors, url) -> None:
    out = REPO / "reports"
    out.mkdir(exist_ok=True)
    data = {"gateway": url, "detectors": detectors, "summary": summary,
            "cases": [{"id": c["id"], "category": c["category"], "lang": c["lang"], "expect": c["expect"],
                       "encode": c.get("encode"), "channel": c.get("channel", "user"), "verdict": v, **r}
                      for c, r, v in rows]}
    (out / "stack_test.json").write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    t = summary["total"]
    md = ["# AICL: full-stack prompt-injection test", "",
          (f"Gateway `{url}`. Attacks detected: **{t['detected']}/{t['attacks']}**, "
           f"false positives: **{t['false_positives']}/{t['benign']}**."), "",
          "| category | attacks detected | false positives |", "|---|---|---|"]
    md += [f"| {k} | {s['detected']}/{s['attacks']} | {s['false_positives']}/{s['benign']} |"
           for k, s in summary["by_category"].items()]
    md += ["", "| language | attacks detected | false positives |", "|---|---|---|"]
    md += [f"| {k} | {s['detected']}/{s['attacks']} | {s['false_positives']}/{s['benign']} |"
           for k, s in summary["by_language"].items()]
    md += ["", "| caught by | cases |", "|---|---|"]
    md += [f"| {k} | {n} |" for k, n in summary["caught_by"].items()]
    md += ["", "| case | category | lang | expected | result | control | ms |", "|---|---|---|---|---|---|---|"]
    md += [f"| {c['id']} | {c['category']} | {c['lang']} | {c['expect']} | {v} | {r.get('control') or r.get('action', '')} "
           f"| {r['wall_ms']:.0f} |" for c, r, v in rows]
    (out / "stack_test.md").write_text("\n".join(md) + "\n", encoding="utf-8")


def main() -> int:
    env = env_files()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=env.get("AICL_DEMO_URL", "http://localhost:8080"))
    ap.add_argument("--key-env", default="AICL_KEY_ADMIN", help="env var with the API key to use")
    ap.add_argument("--category", help="only this category")
    ap.add_argument("--lang", help="only this language")
    ap.add_argument("--verbose", "-v", action="store_true", help="print the blocking reason")
    args = ap.parse_args()

    key = env.get(args.key_env)
    if not key:
        print(f"no API key: set {args.key_env} (see .env.example)")
        return 2
    cases = yaml.safe_load(CASES.read_text(encoding="utf-8"))["cases"]
    cases = [c for c in cases if (not args.category or c["category"] == args.category)
             and (not args.lang or c["lang"] == args.lang)]
    url = args.url.rstrip("/")

    with httpx.Client(base_url=url, timeout=120) as client:
        try:
            health = client.get("/healthz").json()
        except (httpx.HTTPError, ValueError) as exc:
            print(f"gateway not reachable at {url}: {type(exc).__name__}")
            return 2
        detectors = health.get("detectors", {})
        print(f"gateway {url}  policy {health.get('policy_version')}  feed {health.get('feed_version')}")
        for name, d in detectors.items():
            state = "ready" if d.get("ready") else f"NOT READY ({d.get('error') or d.get('backend')})"
            extra = d.get("model") or d.get("backend")
            print(f"  {name:<10} {extra or '-':<28} {state}")
        if not all(d.get("ready") for d in detectors.values()):
            print("  warning: some detectors are not ready; their tiers are skipped in this run")
        print(f"\n{len(cases)} cases\n")

        rows = []
        for case in cases:
            res = run_case(client, case, key)
            v = verdict(case, res)
            rows.append((case, res, v))
            got = (f"BLOCK {res.get('control')}" if res["outcome"] == "block"
                   else f"allow ({res.get('action')})" if res["outcome"] == "allow" else f"ERROR {res.get('detail', '')}")
            mark = {"ok": "ok  ", "MISS": "MISS", "FP": "FP  ", "ERR": "ERR "}[v]
            enc = f" [{case['encode']}]" if case.get("encode") else ""
            chan = f" via {case['channel']}" if case.get("channel", "user") != "user" else ""
            print(f"  {mark} {case['id']:<9} {case['category']:<13} {case['lang']:<3} {got:<28} {res['wall_ms']:6.0f} ms{enc}{chan}")
            if args.verbose and res.get("reason"):
                print(f"         {res['reason']}")

    summary = summarize(rows)
    print("\n== by category")
    for k, s in summary["by_category"].items():
        print(f"  {k:<14} {rate(s)}")
    print("== by language")
    for k, s in summary["by_language"].items():
        print(f"  {k:<14} {rate(s)}")
    print("== caught by")
    for k, n in summary["caught_by"].items():
        note = "" if k in INJECTION_CONTROLS else "  (not an injection control)"
        print(f"  {k or '?':<14} {n}{note}")
    lat = summary["latency_ms"]
    print(f"== latency (wall, incl. mock upstream): blocked p50 {lat['blocked_p50']:.0f} / p95 {lat['blocked_p95']:.0f} ms, "
          f"allowed p50 {lat['allowed_p50']:.0f} / p95 {lat['allowed_p95']:.0f} ms")
    print(f"== TOTAL  {rate(summary['total'])}")
    write_reports(rows, summary, detectors, url)
    print("\nreports/stack_test.md and reports/stack_test.json written")
    t = summary["total"]
    return 0 if t["detected"] == t["attacks"] and t["false_positives"] == 0 and not t["errors"] else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())

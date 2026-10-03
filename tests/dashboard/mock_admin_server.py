#!/usr/bin/env python3
"""Development mock of the AICL admin API + static dashboard (stdlib only, no deps).

NOT part of the gateway. Used to exercise the dashboard against realistic, deterministic
payloads and injected faults. The real gateway serves the dashboard with:

    from fastapi.staticfiles import StaticFiles
    app.mount("/dashboard", StaticFiles(directory="aicl/dashboard", html=True), name="dashboard")

Usage:
    python tests/dashboard/mock_admin_server.py --port 8080                # auth with generated key (printed once)
    python tests/dashboard/mock_admin_server.py --key dev-key-123          # explicit key
    python tests/dashboard/mock_admin_server.py --open                     # local no-auth mode
    python tests/dashboard/mock_admin_server.py --scenario edge            # XSS strings, unknown types, nulls
    python tests/dashboard/mock_admin_server.py --scenario empty|large
    python tests/dashboard/mock_admin_server.py --fail summary=500,latency=429,budgets=timeout,controls=403
    python tests/dashboard/mock_admin_server.py --live                     # appends new events over time

Open http://127.0.0.1:8080/dashboard/
"""
from __future__ import annotations

import argparse
import copy
import json
import secrets
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures_lib as fx

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "aicl" / "dashboard"
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".json": "application/json", ".jsonl": "application/x-ndjson", ".md": "text/markdown; charset=utf-8", ".svg": "image/svg+xml"}

XSS = '<img src=x onerror="alert(1)"><script>alert(2)</script>'


class State:
    def __init__(self, scenario: str, live: bool, seed: int):
        self.lock = threading.Lock()
        self.scenario = scenario
        self.policy_version = fx.POLICY_V_NEW
        self.events = []
        self.delta = timedelta(0)
        self.rng_seed = seed
        if scenario != "empty":
            evs = fx.generate_events(seed)
            self.delta = datetime.now(UTC) - fx.ANCHOR
            self.events = fx.rebase(evs, self.delta)
            if scenario == "large":
                self.events = self._large(self.events)
            if scenario == "edge":
                self.events.extend(self._edge_events())
            self.events.sort(key=lambda e: (e.get("ts") or "") if isinstance(e, dict) else "")
        self.live = live

    def _large(self, base):
        """~20k events: replays the base set shifted back in 7-day steps is too old, so densify the last 24h."""
        out = list(base)
        now = datetime.now(UTC)
        recent = [e for e in base if e.get("type") == "request" and fx.parse_iso(e["ts"]) > now - timedelta(hours=24)]
        k = 0
        while len(out) < 20000 and recent:
            for e in recent:
                c = copy.deepcopy(e)
                c["event_id"] = f"{e['event_id']}x{k}"
                c["request_id"] = f"{e['request_id']}x{k}"
                t = fx.parse_iso(e["ts"]) - timedelta(seconds=(k * 37) % 3600)
                c["ts"] = fx.iso(min(t, now))
                out.append(c)
                if len(out) >= 20000:
                    break
            k += 1
        return out

    def _edge_events(self):
        now = datetime.now(UTC)
        return [
            {"ts": fx.iso(now - timedelta(minutes=3)), "event_id": "evt_edge_xss", "request_id": "req_" + XSS, "session_id": None, "type": "request",
             "endpoint": "chat", "identity": "support-agent-01" + XSS, "role": "support_agent", "profile": "balanced", "policy_version": XSS,
             "feed_version": None, "model": "mock-commercial", "final_action": "block", "would_have_action": None, "shadow": False, "upstream_called": False,
             "decisions": [{"control_id": "C-INJ-PAT", "threat_ids": ["TH-01"], "action": "block", "severity": "high", "reason": XSS,
                            "matches": [{"kind": "email", "masked": XSS, "value": "raw-secret@example.com", "raw": "LEAK", "segment_idx": 0}],
                            "latency_ms": 0.3, "skipped": False}],
             "latency_ms": {"total_overhead": 1.2, "upstream": None, "per_control": {"C-INJ-PAT": 0.3}},
             "usage": {"prompt_tokens": 10, "completion_tokens": 0, "cost_usd": 0, "compute_seconds": 0}, "error": XSS,
             "api_key": "sk-should-never-render", "authorization": "Bearer should-never-render"},
            {"ts": fx.iso(now - timedelta(minutes=2)), "event_id": "evt_edge_unknown", "type": "model.swapped", "final_action": "quarantine",
             "identity": None, "decisions": None, "latency_ms": None, "usage": None},
            {"ts": fx.iso(now - timedelta(minutes=1)), "event_id": "evt_edge_action", "type": "request", "endpoint": "voice", "final_action": "quarantine",
             "identity": "edge-agent", "decisions": [{"control_id": "C-NEW-THING", "action": "quarantine", "severity": "extreme", "threat_ids": ["TH-99"]}]},
            {"event_id": "evt_edge_no_ts", "type": "request", "final_action": "allow"},
            "not-an-object",
        ]

    def append_live(self):
        """Adds a few fresh request events derived from the deterministic generator (cycled)."""
        import random
        rng = random.Random(self.rng_seed + int(time.time()) // 5)
        now = datetime.now(UTC)
        sessions = {}
        new = []
        for i in range(rng.choice((0, 0, 1, 1, 2))):  # ≈ 10 req/min
            ident = fx.IDENTITIES[rng.randrange(len(fx.IDENTITIES))]
            sc = fx.SCENARIOS[rng.choices(range(len(fx.SCENARIOS)), [s[1] for s in fx.SCENARIOS])[0]]
            ev = fx._make_request(rng, now - timedelta(milliseconds=200 * i), ident, sc, sessions)
            ev["policy_version"], ev["feed_version"] = self.policy_version, fx.FEED_V_NEW
            new.append(ev)
        with self.lock:
            self.events.extend(sorted(new, key=lambda e: e["ts"]))

    # ---- payloads
    def now(self):
        return datetime.now(UTC)

    def req_events(self):
        return [e for e in self.events if isinstance(e, dict) and e.get("ts")]

    def payload(self, name):
        if self.scenario == "empty":
            return {"healthz": {"status": "ok"}, "summary": {}, "latency": {}, "budgets": {"identities": []},
                    "controls": {"controls": []}, "policy": {}, "tests": None, "fuzz": None}[name]
        evs = self.req_events()
        now = self.now()
        if name == "healthz":
            return {"status": "ok", "policy_version": self.policy_version, "feed_version": fx.FEED_V_NEW}
        if name == "summary":
            p = fx.summary(evs, now)
            if self.scenario == "edge":
                p.pop("previous", None)
                p["by_action"]["quarantine"] = 2
                p["by_threat"] = None
            return p
        if name == "latency":
            p = fx.latency(evs, now)
            if self.scenario == "edge":
                p["upstream"] = None
                p["per_control"]["C-NEW-THING"] = {"p50": None, "p95": None}
            return p
        if name == "budgets":
            p = fx.budgets(evs, now)
            if self.scenario == "edge":
                p["identities"][0]["limits"] = {"max_tokens": None, "max_cost_usd": 0}
                p["identities"].append({"identity": XSS, "usage": None, "limits": None})
            return p
        if name == "controls":
            p = fx.controls_payload()
            if self.scenario == "edge":
                p["controls"].append({"id": "C-NEW-THING", "name": XSS, "levels": None, "stages": None, "threat_ids": ["TH-99"]})
            return p
        if name == "policy":
            p = fx.policy_payload(now)
            p["policy_version"] = self.policy_version
            return fx.rebase(p, self.delta)
        if name == "tests":
            return fx.rebase(fx.test_report(fx.ANCHOR), self.delta)
        if name == "fuzz":
            return fx.rebase(fx.fuzz_report(fx.ANCHOR), self.delta)
        raise KeyError(name)


def parse_faults(spec: str | None):
    out = {}
    for part in (spec or "").split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


ROUTES = {
    "/healthz": "healthz", "/admin/metrics/summary": "summary", "/admin/metrics/latency": "latency", "/admin/metrics/budgets": "budgets",
    "/admin/events": "events", "/admin/controls": "controls", "/admin/policy": "policy", "/admin/export/audit.jsonl": "export",
    "/admin/policy/validate": "validate", "/admin/policy/reload": "reload", "/reports/test_report.json": "tests", "/reports/fuzz_latest.json": "fuzz",
}


def make_handler(state: State, key: str | None, faults: dict):
    class H(BaseHTTPRequestHandler):
        server_version = "aicl-mock/1"

        def log_message(self, fmt, *args):  # never log headers (Authorization)
            sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))

        def _send(self, status, body=b"", ctype="application/json", extra=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _static(self, path):
            rel = path[len("/dashboard"):].lstrip("/") or "index.html"
            target = (STATIC / rel).resolve()
            if not str(target).startswith(str(STATIC.resolve())) or not target.is_file():
                return self._send(404, {"detail": "Not Found"})
            self._send(200, target.read_bytes(), MIME.get(target.suffix, "application/octet-stream"))

        def _auth_ok(self):
            if key is None:
                return True
            return self.headers.get("Authorization", "") == f"Bearer {key}"

        def _route(self, method):
            url = urlparse(self.path)
            path = url.path
            if path in ("/", "/dashboard"):
                return self._send(302, b"", extra={"Location": "/dashboard/"})
            if path.startswith("/dashboard/"):
                return self._static(path)
            name = ROUTES.get(path)
            if not name:
                return self._send(404, {"detail": "Not Found"})
            if name in ("validate", "reload") and method != "POST":
                return self._send(405, {"detail": "Method Not Allowed"})
            if name not in ("validate", "reload") and method == "POST":
                return self._send(405, {"detail": "Method Not Allowed"})
            if name not in ("healthz", "tests", "fuzz") and not self._auth_ok():
                return self._send(401, {"detail": "Invalid or missing admin key"}, extra={"WWW-Authenticate": "Bearer"})
            fault = faults.get(name) or faults.get("all")
            if fault:
                if fault == "timeout":
                    time.sleep(30)
                    return self._send(504, {"detail": "timeout"})
                code = int(fault)
                extra = {"Retry-After": "7"} if code == 429 else None
                return self._send(code, {"detail": f"Injected fault {code} for {name}"}, extra=extra)
            q = {k: v[-1] for k, v in parse_qs(url.query).items()}
            if name == "events":
                return self._events(q)
            if name == "export":
                with state.lock:
                    lines = [json.dumps(e) for e in state.events if isinstance(e, dict)]
                return self._send(200, "\n".join(lines) + "\n", "application/x-ndjson",
                                  {"Content-Disposition": 'attachment; filename="audit.jsonl"'})
            if name == "validate":
                return self._validate()
            if name == "reload":
                return self._reload()
            with state.lock:
                body = state.payload(name)
            if body is None:
                return self._send(404, {"detail": "Report not generated"})
            self._send(200, body)

        def _events(self, q):
            limit = max(1, min(int(q.get("limit", 2000) or 2000), 50000))
            since = q.get("since")
            with state.lock:
                evs = list(state.events)
            out = []
            for e in reversed(evs):
                if len(out) >= limit:
                    break
                if isinstance(e, dict):
                    if since and (e.get("ts") or "") < since:
                        continue
                    if q.get("action") and e.get("final_action") != q["action"]:
                        continue
                    if q.get("identity") and e.get("identity") != q["identity"]:
                        continue
                    if q.get("control") and not any((d or {}).get("control_id") == q["control"] for d in e.get("decisions") or []):
                        continue
                out.append(e)
            self._send(200, out)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(min(n, 2_000_000)).decode("utf-8", "replace")

        def _validate(self):
            raw = self._body()
            ctype = self.headers.get("Content-Type", "")
            text = raw
            if "json" in ctype:
                try:
                    j = json.loads(raw)
                    text = j.get("policy") or j.get("yaml") or j.get("content") or "" if isinstance(j, dict) else ""
                except ValueError:
                    return self._send(400, {"detail": "Body is not valid JSON"})
            errors = []
            if not text.strip():
                errors.append({"loc": ["body"], "msg": "Field required", "type": "missing"})
            for i, line in enumerate(text.splitlines(), 1):
                s = line.strip()
                if s.startswith("active_profile:") and s.split(":", 1)[1].strip() not in ("strict", "balanced", "permissive"):
                    errors.append({"loc": ["active_profile"], "msg": "Input should be 'strict', 'balanced' or 'permissive'", "type": "literal_error", "line": i})
                if s.startswith("mode:") and s.split(":", 1)[1].strip() not in ("enforce", "shadow"):
                    errors.append({"loc": ["mode"], "msg": "Input should be 'enforce' or 'shadow'", "type": "literal_error", "line": i})
                if s.startswith("threshold:"):
                    try:
                        v = float(s.split(":", 1)[1])
                        if not 0 <= v <= 1:
                            errors.append({"loc": ["controls", "injection_semantic", "levels", "?", "threshold"], "msg": "Input should be less than or equal to 1", "type": "less_than_equal", "line": i})
                    except ValueError:
                        errors.append({"loc": ["controls", "?", "threshold"], "msg": "Input should be a valid number", "type": "float_parsing", "line": i})
                if "\t" in line:
                    errors.append({"loc": ["<yaml>"], "msg": f"YAML: tab character at line {i}", "type": "yaml_error", "line": i})
            if "version:" not in text and text.strip():
                errors.append({"loc": ["version"], "msg": "Field required", "type": "missing"})
            if errors:
                return self._send(422, {"valid": False, "errors": errors})
            self._send(200, {"valid": True, "errors": [], "warnings": [{"loc": ["semantic", "model"], "msg": "Placeholder model name (mock validator)"}]})

        def _reload(self):
            now = datetime.now(UTC)
            with state.lock:
                ev = {"ts": fx.iso(now), "event_id": f"evt_reload_{int(now.timestamp())}", "type": "policy.reloaded", "request_id": None,
                      "policy_version": state.policy_version, "feed_version": fx.FEED_V_NEW, "reason": "Manual reload via admin API (mock)", "error": None}
                state.events.append(ev)
            self._send(200, {"status": "ok", "policy_version": state.policy_version, "loaded_at": ev["ts"]})

        def do_GET(self):
            self._route("GET")

        def do_HEAD(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")

    return H


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--key", help="admin key expected in 'Authorization: Bearer <key>'")
    g.add_argument("--open", action="store_true", help="local no-auth mode")
    ap.add_argument("--scenario", choices=["normal", "empty", "edge", "large"], default="normal")
    ap.add_argument("--fail", help="faults: endpoint=status|timeout,... (endpoints: %s, all)" % ",".join(sorted(set(ROUTES.values()))))
    ap.add_argument("--live", action="store_true", help="append new events every ~5 s")
    ap.add_argument("--seed", type=int, default=fx.SEED)
    a = ap.parse_args()
    key = None if a.open else (a.key or secrets.token_urlsafe(18))
    state = State(a.scenario, a.live, a.seed)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(state, key, parse_faults(a.fail)))
    if a.live:
        def loop():
            while True:
                time.sleep(5)
                state.append_live()
        threading.Thread(target=loop, daemon=True).start()
    print(f"AICL mock admin API on http://{a.host}:{a.port}/dashboard/  scenario={a.scenario} auth={'off' if key is None else 'on'}", file=sys.stderr)
    if key and not a.key:
        print(f"generated dev admin key (shown once): {key}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

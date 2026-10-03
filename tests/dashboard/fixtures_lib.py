"""Deterministic DEMO fixtures for the AICL dashboard (R5).

Everything here is synthetic and clearly fake. The same seed always yields the same
events, so the dashboard's DEMO DATA mode and the dev mock server are reproducible.

Produces payloads in the shapes the dashboard normaliser documents (aicl/dashboard/normalize.js):
  audit events (ARCHITECTURE §8 contract), /healthz, /admin/metrics/{summary,latency,budgets},
  /admin/controls, /admin/policy, reports/test_report.json (§11.6), fuzz report (§11.7).

Aggregations (summary/latency/budgets) are computed from the events, so they always agree.
"""
from __future__ import annotations

import hashlib
import math
import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

SEED = 20261003
ANCHOR = datetime(2026, 10, 4, 12, 47, 0, tzinfo=timezone.utc)
POLICY_V_OLD = "a3f9c1d2e4b7"
POLICY_V_NEW = "7c1e09b4d2aa"
FEED_V_OLD = "2026-10-03.1"
FEED_V_NEW = "2026-10-04.1"
POLICY_CHANGE_AT = ANCHOR - timedelta(hours=3)
FEED_CHANGE_AT = ANCHOR - timedelta(minutes=50)
SUMMARY_WINDOW = timedelta(hours=24)
JUDGE = "C-INJ-SEM"

THREATS = [
    ("TH-01", "Direct prompt injection", ["LLM01:2025 Prompt Injection"], ["AML.T0051.000"]),
    ("TH-02", "Indirect prompt injection", ["LLM01:2025 Prompt Injection"], ["AML.T0051.001"]),
    ("TH-03", "PII in input", ["LLM02:2025 Sensitive Information Disclosure"], ["AML.T0057"]),
    ("TH-04", "Secrets leakage", ["LLM02:2025 Sensitive Information Disclosure"], ["AML.T0057"]),
    ("TH-05", "PII leakage in output", ["LLM02:2025 Sensitive Information Disclosure"], ["AML.T0057"]),
    ("TH-06", "Disallowed model", ["LLM03:2025 Supply Chain"], []),
    ("TH-07", "Excessive agency / unauthorized tool", ["LLM06:2025 Excessive Agency"], ["AML.T0053"]),
    ("TH-08", "Impersonation / missing auth", ["LLM06:2025 Excessive Agency"], []),
    ("TH-09", "Delegation / privilege escalation", ["LLM06:2025 Excessive Agency"], []),
    ("TH-10", "Unauthorized memory / RAG access", ["LLM08:2025 Vector and Embedding Weaknesses"], []),
    ("TH-11", "Token overuse", ["LLM10:2025 Unbounded Consumption"], ["AML.T0034"]),
    ("TH-12", "Cost / compute overuse", ["LLM10:2025 Unbounded Consumption"], ["AML.T0034"]),
    ("TH-13", "Runaway agent loops", ["LLM10:2025 Unbounded Consumption"], ["AML.T0029"]),
    ("TH-14", "Unsafe deserialization (pickle)", ["LLM03:2025 Supply Chain"], ["AML.T0011.000"]),
    ("TH-15", "Malicious code execution", ["LLM05:2025 Improper Output Handling"], []),
    ("TH-16", "Model-repo / package supply chain", ["LLM03:2025 Supply Chain"], ["AML.T0010"]),
    ("TH-17", "Known historical attack signatures", ["LLM01:2025 Prompt Injection"], []),
    ("TH-18", "System-prompt / canary leakage", ["LLM07:2025 System Prompt Leakage"], ["AML.T0056"]),
    ("TH-19", "Injection-driven privileged action", ["LLM06:2025 Excessive Agency"], ["AML.T0051.001"]),
    ("TH-20", "Oversized input / DoS", ["LLM10:2025 Unbounded Consumption"], ["AML.T0029"]),
]

def lv(strict, balanced, permissive, **extra):
    out = {}
    for name, act in (("strict", strict), ("balanced", balanced), ("permissive", permissive)):
        out[name] = {"action": act}
        for k, v in extra.items():
            out[name][k] = v[name] if isinstance(v, dict) else v
    return out

CONTROLS = [
    # id, key, name, stages, threats, priority, tier, type, levels, enabled, mode
    ("C-AUTH", None, "Authentication", ["ingress"], ["TH-08"], 1, "P0", "deterministic", lv("block", "block", "block"), True, None),
    ("C-MODEL-ALLOW", "model_allowlist", "Model allowlist", ["ingress"], ["TH-06"], 5, "P0", "deterministic", lv("block", "block", "block"), True, None),
    ("C-SIZE", "size_limits", "Size limits", ["ingress"], ["TH-20"], 6, "P0", "deterministic", lv("block", "block", "flag"), True, None),
    ("C-BUDGET", "budget_guard", "Budget guard", ["ingress", "output"], ["TH-11", "TH-12"], 8, "P0", "deterministic", lv("block", "block", "flag"), True, None),
    ("C-INJ-PAT", "injection_patterns", "Injection patterns", ["input", "tool_result"], ["TH-01", "TH-02"], 20, "P0", "deterministic",
     lv("block", "block", "flag", min_severity={"strict": "low", "balanced": "medium", "permissive": "high"}), True, None),
    ("C-SIG", "signature_feed", "Signature feed", ["ingress", "input", "tool_call", "tool_result", "output", "artifact"], ["TH-17"], 22, "P0", "deterministic", lv("block", "block", "flag"), True, None),
    ("C-PII-IN", "pii_input", "PII in input", ["input"], ["TH-03"], 30, "P0", "deterministic", lv("block", "redact", "flag"), True, None),
    ("C-SECRET-IN", "secrets_input", "Secrets in input", ["input"], ["TH-04"], 31, "P0", "deterministic", lv("block", "block", "redact"), True, None),
    ("C-TOOL-ACL", "tool_acl", "Tool ACL", ["tool_call"], ["TH-07"], 40, "P0", "deterministic", lv("block", "block", "flag", validate_args={"strict": True, "balanced": True, "permissive": False}), True, None),
    ("C-LOOP", "loop_guard", "Loop guard", ["tool_call"], ["TH-13"], 42, "P0", "deterministic", lv("block", "block", "flag"), True, None),
    ("C-MEM-ACL", "memory_acl", "Memory / RAG ACL", ["tool_call", "input"], ["TH-10"], 44, "P1", "deterministic", lv("block", "block", "flag"), True, None),
    ("C-TAINT", "taint", "Taint tracking", ["tool_call"], ["TH-19"], 46, "P2", "deterministic", lv("block", "require_approval", "flag"), True, None),
    ("C-DELEG", "delegation", "Delegation depth", ["ingress", "tool_call"], ["TH-09"], 48, "P2", "deterministic", lv("block", "block", "flag"), False, None),
    ("C-CODE-EXEC", "code_exec_patterns", "Code execution patterns", ["tool_call", "output"], ["TH-15"], 50, "P0", "deterministic", lv("block", "block", "flag"), True, None),
    ("C-ARTIFACT", "artifact_scan", "Artifact scan (pickle)", ["artifact"], ["TH-14"], 55, "P0", "deterministic", lv("block", "block", "flag"), True, None),
    ("C-SUPPLY", "supply_chain", "Supply chain", ["ingress", "artifact", "tool_call"], ["TH-16"], 57, "P1", "deterministic", lv("block", "block", "flag"), True, "shadow"),
    ("C-PII-OUT", "pii_output", "PII in output", ["output", "tool_result"], ["TH-05"], 60, "P0", "deterministic", lv("block", "redact", "flag"), True, None),
    ("C-SECRET-OUT", "secrets_output", "Secrets in output", ["output", "tool_result", "input"], ["TH-04"], 61, "P0", "deterministic", lv("block", "redact", "redact"), True, None),
    ("C-CANARY", "canary", "Canary tokens", ["output", "tool_call"], ["TH-18"], 65, "P1", "deterministic", lv("block", "block", "block"), True, None),
    ("C-INJ-SEM", "injection_semantic", "Semantic injection judge", ["input", "tool_result"], ["TH-01", "TH-02"], 500, "P1", "semantic",
     lv("block", "block", "flag", threshold={"strict": 0.5, "balanced": 0.7, "permissive": 0.85}), True, None),
]
CONTROL_BY_ID = {c[0]: c for c in CONTROLS}

IDENTITIES = [
    # id, role, profile, weight, models
    ("support-agent-01", "support_agent", "balanced", 0.50, ["mock-commercial"]),
    ("support-agent-02", "support_agent", "balanced", 0.18, ["mock-commercial"]),
    ("research-agent-01", "researcher", "strict", 0.20, ["ollama-local"]),
    ("sandbox-agent-07", "tester", "permissive", 0.10, ["mock-commercial", "ollama-local"]),
    ("admin", "admin", "balanced", 0.02, ["mock-commercial"]),
]
BUDGETS = {
    "support_default": {"window": "day", "max_tokens": 175000, "max_cost_usd": 0.20, "max_compute_seconds": 600, "max_requests_per_minute": 30, "max_tool_calls_per_session": 25, "on_exceed": "block"},
    "research_default": {"window": "day", "max_tokens": 200000, "max_cost_usd": None, "max_compute_seconds": 1800, "max_requests_per_minute": 20, "max_tool_calls_per_session": 40, "on_exceed": "block"},
    "tester_default": {"window": "hour", "max_tokens": 6500, "max_cost_usd": 0.02, "max_compute_seconds": 120, "max_requests_per_minute": 10, "max_tool_calls_per_session": 10, "on_exceed": "block"},
    "unlimited": {},
}
ROLE_BUDGET = {"support_agent": "support_default", "researcher": "research_default", "tester": "tester_default", "admin": "unlimited"}
PRICES = {"mock-commercial": (0.0005, 0.0015), "ollama-local": (0.0, 0.0)}

# Scenario: (name, weight, endpoint, control, action_by_profile, severity, threats, upstream_called, reason, matches)
SCENARIOS = [
    ("benign_chat", 0.600, "chat", None, None, None, None, True, "", []),
    ("benign_tool", 0.085, "tool_invoke", None, None, None, None, True, "", []),
    ("benign_mcp", 0.040, "mcp", None, None, None, None, True, "", []),
    ("inj_direct", 0.045, "chat", "C-INJ-PAT", "block", "high", ["TH-01"], False, "Instruction override pattern: 'ignore all previous instructions'", []),
    ("inj_semantic", 0.012, "chat", "C-INJ-SEM", "block", "high", ["TH-01"], False, "Judge: paraphrased role-override attempt", []),
    ("inj_indirect", 0.020, "tool_invoke", "C-INJ-PAT", "block", "high", ["TH-02"], True, "Hidden instruction in tool result (poisoned document)", []),
    ("pii_out", 0.050, "chat", "C-PII-OUT", "redact", "medium", ["TH-05"], True, "Email and PESEL in model output",
     [{"kind": "email", "segment_idx": 2, "masked": "j***.k******@example.com"}, {"kind": "pesel", "segment_idx": 2, "masked": "*******0123"}]),
    ("pii_in", 0.015, "chat", "C-PII-IN", "redact", "low", ["TH-03"], True, "Phone number in user prompt", [{"kind": "phone_pl", "segment_idx": 0, "masked": "+48 *** *** 789"}]),
    ("secret_out", 0.020, "chat", "C-SECRET-OUT", "redact", "high", ["TH-04"], True, "AWS access key in model output", [{"kind": "aws_access_key", "segment_idx": 3, "masked": "AKIA****************"}]),
    ("secret_in", 0.008, "chat", "C-SECRET-IN", "block", "critical", ["TH-04"], False, "Private key block in prompt", [{"kind": "private_key_block", "segment_idx": 0, "masked": "-----BEGIN ******** KEY-----"}]),
    ("tool_acl", 0.015, "tool_invoke", "C-TOOL-ACL", "block", "high", ["TH-07"], False, "Tool run_shell not allowed for role", []),
    ("code_exec", 0.009, "tool_invoke", "C-CODE-EXEC", "block", "critical", ["TH-15"], False, "curl | sh pattern in tool arguments", [{"kind": "curl_pipe_sh", "segment_idx": 0, "masked": "curl ****** | sh"}]),
    ("artifact", 0.008, "artifact_scan", "C-ARTIFACT", "block", "critical", ["TH-14"], False, "Pickle GLOBAL os.system before REDUCE", [{"kind": "pickle_global", "masked": "os.system"}]),
    ("signature", 0.010, "chat", "C-SIG", "block", "high", ["TH-17"], False, "Matched SIG-INJ-014 (DAN-style jailbreak)", []),
    ("taint", 0.008, "tool_invoke", "C-TAINT", "require_approval", "high", ["TH-19"], False, "send_email (privilege high) in tainted session", []),
    ("loop", 0.006, "tool_invoke", "C-LOOP", "block", "medium", ["TH-13"], False, "4 identical search_docs calls within 60 s", []),
    ("canary", 0.004, "chat", "C-CANARY", "block", "critical", ["TH-18"], True, "Canary token found in model output", [{"kind": "canary", "segment_idx": 2, "masked": "CANARY-****-****"}]),
    ("model", 0.006, "chat", "C-MODEL-ALLOW", "block", "medium", ["TH-06"], False, "Model gpt-unlisted not in allowlist for role", []),
    ("mem", 0.005, "tool_invoke", "C-MEM-ACL", "block", "high", ["TH-10"], False, "Namespace kb_hr not allowed for role", []),
    ("supply_shadow", 0.006, "artifact_scan", "C-SUPPLY", "block", "medium", ["TH-16"], False, "Unpinned model repo reference (shadow mode)", []),
    ("size", 0.004, "chat", "C-SIZE", "block", "medium", ["TH-20"], False, "Input 412 KB exceeds 256 KB limit", []),
    ("budget", 0.004, "chat", "C-BUDGET", "block", "medium", ["TH-11"], False, "Daily token budget exhausted", []),
]

BASE_STAGE_CONTROLS = {
    "chat": ["C-MODEL-ALLOW", "C-SIZE", "C-BUDGET", "C-INJ-PAT", "C-SIG", "C-PII-IN", "C-SECRET-IN", "C-INJ-SEM", "C-PII-OUT", "C-SECRET-OUT", "C-CANARY", "C-CODE-EXEC"],
    "tool_invoke": ["C-BUDGET", "C-TOOL-ACL", "C-LOOP", "C-MEM-ACL", "C-TAINT", "C-CODE-EXEC", "C-SIG", "C-INJ-PAT", "C-INJ-SEM", "C-PII-OUT", "C-SECRET-OUT"],
    "mcp": ["C-BUDGET", "C-TOOL-ACL", "C-LOOP", "C-TAINT", "C-SIG", "C-INJ-PAT", "C-INJ-SEM", "C-PII-OUT"],
    "artifact_scan": ["C-SIZE", "C-ARTIFACT", "C-SUPPLY", "C-SIG"],
}
CTL_BASE_MS = {
    "C-MODEL-ALLOW": 0.02, "C-SIZE": 0.01, "C-BUDGET": 0.04, "C-INJ-PAT": 0.42, "C-SIG": 0.31, "C-PII-IN": 0.28, "C-SECRET-IN": 0.19,
    "C-PII-OUT": 0.36, "C-SECRET-OUT": 0.22, "C-CANARY": 0.05, "C-CODE-EXEC": 0.12, "C-TOOL-ACL": 0.06, "C-LOOP": 0.05, "C-MEM-ACL": 0.04,
    "C-TAINT": 0.03, "C-ARTIFACT": 2.8, "C-SUPPLY": 0.4, "C-INJ-SEM": 210.0,
}


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_iso(s: str) -> datetime:
    return datetime.strptime(s.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f%z")


def _ulid(rng: random.Random, prefix: str) -> str:
    return prefix + "".join(rng.choice("0123456789ABCDEFGHJKMNPQRSTVWXYZ") for _ in range(20))


def _rate_per_min(t: datetime) -> float:
    age_h = (ANCHOR - t).total_seconds() / 3600
    base = 2.0 if age_h < 2 else 0.4 if age_h < 48 else 0.04
    # daily rhythm + an injection campaign 4h–4h20m ago
    base *= 0.75 + 0.5 * math.sin((t.hour + t.minute / 60) / 24 * 2 * math.pi - 1.2) ** 2
    return base


def _campaign(t: datetime) -> bool:
    age_m = (ANCHOR - t).total_seconds() / 60
    return 240 <= age_m <= 262


def generate_events(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    events: list[dict] = []
    t = ANCHOR - timedelta(days=7)
    sessions: dict[str, tuple[str, int]] = {}
    weights = [s[1] for s in SCENARIOS]
    while t < ANCHOR:
        rate = _rate_per_min(t) * (4.0 if _campaign(t) else 1.0)
        t += timedelta(seconds=rng.expovariate(rate / 60.0))
        if t >= ANCHOR:
            break
        r = rng.random()
        acc = 0.0
        ident = IDENTITIES[0]
        for it in IDENTITIES:
            acc += it[3]
            if r <= acc:
                ident = it
                break
        sc = SCENARIOS[rng.choices(range(len(SCENARIOS)), weights)[0]]
        if _campaign(t) and rng.random() < 0.55:
            sc = SCENARIOS[3] if rng.random() < 0.7 else SCENARIOS[13]
            ident = IDENTITIES[1]
        events.append(_make_request(rng, t, ident, sc, sessions))
    events.extend(_system_events(rng))
    events.sort(key=lambda e: e["ts"])
    return events


def _make_request(rng, t, ident, sc, sessions):
    name, _w, endpoint, ctl, action, severity, threats, upstream_called, reason, matches = sc
    ident_id, role, profile, _wt, models = ident
    model = rng.choice(models) if endpoint in ("chat",) else None
    sess, n = sessions.get(ident_id, (None, 99))
    if n >= rng.randint(6, 30):
        sess, n = "sess_" + hashlib.sha1(f"{ident_id}{t.isoformat()}".encode()).hexdigest()[:10], 0
    sessions[ident_id] = (sess, n + 1)
    policy_v = POLICY_V_NEW if t >= POLICY_CHANGE_AT else POLICY_V_OLD
    feed_v = FEED_V_NEW if t >= FEED_CHANGE_AT else FEED_V_OLD

    final = "allow"
    would = None
    acting = None
    if ctl:
        lvl = CONTROL_BY_ID[ctl][8].get(profile, {})
        act = lvl.get("action", action)
        if ctl == "C-TAINT":
            act = action if profile == "balanced" else act
        acting = {"control_id": ctl, "threat_ids": threats, "action": act, "severity": severity,
                  "score": round(rng.uniform(0.72, 0.97), 2) if ctl == JUDGE else None, "reason": reason,
                  "matches": [dict(m) for m in matches], "latency_ms": 0.0, "skipped": False, "shadow_suppressed": False}
        if CONTROL_BY_ID[ctl][10] == "shadow":
            acting["shadow_suppressed"] = True
            would = act
        else:
            final = act
    # upstream is reached unless an ingress/input/tool_call control stopped the request first
    output_stage = ctl in ("C-PII-OUT", "C-SECRET-OUT", "C-CANARY") or name == "inj_indirect"
    if endpoint == "artifact_scan":
        upstream_called = False
    elif final in ("allow", "flag", "redact") or output_stage:
        upstream_called = True
    else:
        upstream_called = False
    judged = name in ("inj_semantic", "inj_indirect") or (endpoint in ("tool_invoke", "mcp") and rng.random() < 0.07) or rng.random() < 0.004
    decisions = []
    per_control = {}
    stop = False
    for cid in BASE_STAGE_CONTROLS[endpoint]:
        if stop:
            break
        base = CTL_BASE_MS[cid]
        if cid == JUDGE:
            ms = round(rng.lognormvariate(math.log(base), 0.45), 2) if judged else 0.01
        else:
            ms = round(rng.lognormvariate(math.log(base), 0.35), 3)
        per_control[cid] = ms
        if acting and cid == acting["control_id"]:
            acting["latency_ms"] = ms
            decisions.append(acting)
            if acting["action"] in ("block", "require_approval") and not acting["shadow_suppressed"]:
                stop = True
            continue
        if cid == JUDGE and not judged:
            del per_control[cid]  # judge skipped (not in grey zone): cheap path, nothing to record
            continue
        if cid == JUDGE:  # allow decisions of cheap controls are summarised in latency_ms.per_control only
            decisions.append({"control_id": cid, "threat_ids": ["TH-01", "TH-02"], "action": "allow", "severity": "low",
                              "score": round(rng.uniform(0.02, 0.4), 2), "reason": "judge: benign", "matches": [], "latency_ms": ms, "skipped": False, "shadow_suppressed": False})
    if acting and acting not in decisions:
        decisions.append(acting)
        per_control[acting["control_id"]] = acting["latency_ms"] = round(rng.lognormvariate(math.log(CTL_BASE_MS.get(acting["control_id"], 0.1)), 0.3), 3)
    overhead = round(sum(per_control.values()) + rng.uniform(0.4, 1.4), 2)
    up_ms = 0.0
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0, "compute_seconds": 0.0}
    if upstream_called:
        if endpoint == "chat":
            up_ms = round(rng.lognormvariate(math.log(650 if model == "mock-commercial" else 1400), 0.4), 1)
            pt, ct = rng.randint(60, 900), rng.randint(20, 700)
            pin, pout = PRICES[model]
            usage = {"prompt_tokens": pt, "completion_tokens": ct, "cost_usd": round(pt / 1000 * pin + ct / 1000 * pout, 6),
                     "compute_seconds": round(up_ms / 1000, 3) if model == "ollama-local" else 0.0}
        else:
            up_ms = round(rng.lognormvariate(math.log(120), 0.5), 1)
    return {
        "ts": iso(t), "event_id": _ulid(rng, "evt_01J"), "request_id": _ulid(rng, "req_01J"), "session_id": sess,
        "type": "request", "endpoint": endpoint, "identity": ident_id, "role": role, "profile": profile,
        "policy_version": policy_v, "feed_version": feed_v, "model": model, "final_action": final,
        "would_have_action": would, "shadow": False, "upstream_called": upstream_called, "decisions": decisions,
        "latency_ms": {"total_overhead": overhead, "upstream": up_ms if upstream_called else None, "per_control": per_control},
        "usage": usage, "error": None,
    }


def _system_events(rng):
    def ev(t, typ, **kw):
        base = {"ts": iso(t), "event_id": _ulid(rng, "evt_01J"), "request_id": None, "session_id": None, "type": typ,
                "policy_version": POLICY_V_NEW if t >= POLICY_CHANGE_AT else POLICY_V_OLD,
                "feed_version": FEED_V_NEW if t >= FEED_CHANGE_AT else FEED_V_OLD, "error": None}
        base.update(kw)
        return base
    out = [
        ev(ANCHOR - timedelta(days=6, hours=3), "policy.reloaded", reason="Policy loaded at startup (default-policy)"),
        ev(ANCHOR - timedelta(days=2, hours=5), "feed.reloaded", reason="historical-attacks: 64 signatures"),
        ev(POLICY_CHANGE_AT - timedelta(minutes=5), "policy.rejected", policy_version=POLICY_V_OLD, reason="Validation failed — previous policy kept",
           error="controls.injection_semantic.levels.balanced.threshold: Input should be less than or equal to 1"),
        ev(POLICY_CHANGE_AT, "policy.reloaded", reason="Hot reload: injection_semantic.balanced.threshold 0.75 → 0.70"),
        ev(FEED_CHANGE_AT, "feed.reloaded", reason="historical-attacks: 71 signatures (+7)"),
    ]
    for minutes in (38, 31, 17):
        out.append(ev(ANCHOR - timedelta(minutes=minutes), "budget.exceeded", identity="sandbox-agent-07", role="tester", profile="permissive",
                      reason="tester_default: max_tokens 6500 per hour exceeded"))
    out.append(ev(ANCHOR - timedelta(hours=9), "budget.exceeded", identity="support-agent-02", role="support_agent", profile="balanced",
                  reason="support_default: max_requests_per_minute 30 exceeded"))
    return out


# ---------------------------------------------------------------------------- aggregations

def _pct(sorted_vals, p):
    if not sorted_vals:
        return None
    idx = min(len(sorted_vals) - 1, max(0, math.ceil(p / 100 * len(sorted_vals)) - 1))
    return round(sorted_vals[idx], 3)


def _block(vals):
    vals = sorted(v for v in vals if v is not None)
    if not vals:
        return None
    return {"p50": _pct(vals, 50), "p95": _pct(vals, 95), "p99": _pct(vals, 99), "count": len(vals)}


def _acting(e):
    return [d for d in e.get("decisions") or [] if not d.get("skipped") and (d.get("action") != "allow" or d.get("shadow_suppressed"))]


def _counts(evs):
    by_action = Counter(e.get("final_action") or "unknown" for e in evs)
    return {"requests_total": len(evs), "by_action": {a: by_action.get(a, 0) for a in ("allow", "flag", "redact", "require_approval", "block")},
            "cost_usd": round(sum((e.get("usage") or {}).get("cost_usd") or 0 for e in evs), 6)}


def summary(events, now: datetime, bucket=timedelta(minutes=5)):
    req = [e for e in events if e.get("type") == "request"]
    win_from = now - SUMMARY_WINDOW
    cur = [e for e in req if parse_iso(e["ts"]) > win_from]
    prev = [e for e in req if now - 2 * SUMMARY_WINDOW < parse_iso(e["ts"]) <= win_from]
    by_ctl, by_thr, by_sev, by_owasp = Counter(), Counter(), Counter(), Counter()
    owasp = {t[0]: t[2] for t in THREATS}
    for e in cur:
        acting = _acting(e)
        for d in acting:
            by_ctl[d["control_id"]] += 1
            by_sev[d.get("severity") or "unknown"] += 1
        for t in {t for d in acting for t in d.get("threat_ids", [])}:
            by_thr[t] += 1
            for o in owasp.get(t, []):
                by_owasp[o] += 1
    judged = sum(1 for e in cur if any(d["control_id"] == JUDGE and not d.get("skipped") for d in e.get("decisions") or []))
    # timeseries over 7 days so all dashboard ranges can be re-bucketed
    start = now - timedelta(days=7)
    nb = int((now - start) / bucket)
    series = [defaultdict(int) for _ in range(nb)]
    for e in req:
        i = int((parse_iso(e["ts"]) - start) / bucket)
        if 0 <= i < nb:
            series[i][e.get("final_action") or "unknown"] += 1
    points = [{"ts": iso(start + i * bucket), **{a: s.get(a, 0) for a in ("allow", "flag", "redact", "require_approval", "block")}} for i, s in enumerate(series)]
    return {
        "window": {"from": iso(win_from), "to": iso(now)},
        **_counts(cur),
        "previous": _counts(prev),
        "by_control": dict(by_ctl.most_common()),
        "by_threat": dict(by_thr.most_common()),
        "by_identity": dict(Counter(e.get("identity") for e in cur).most_common()),
        "by_owasp": dict(by_owasp.most_common()),
        "by_severity": dict(by_sev),
        "by_endpoint": dict(Counter(e.get("endpoint") for e in cur)),
        "semantic": {"judged": judged, "skipped": len(cur) - judged},
        "timeseries": {"bucket_seconds": int(bucket.total_seconds()), "points": points},
    }


def latency(events, now: datetime):
    cur = [e for e in events if e.get("type") == "request" and parse_iso(e["ts"]) > now - SUMMARY_WINDOW]
    per = defaultdict(list)
    for e in cur:
        for k, v in ((e.get("latency_ms") or {}).get("per_control") or {}).items():
            if k == JUDGE and not any(d["control_id"] == JUDGE and not d.get("skipped") for d in e.get("decisions") or []):
                continue
            per[k].append(v)
    judged = [e["latency_ms"]["per_control"][JUDGE] for e in cur if any(d["control_id"] == JUDGE and not d.get("skipped") for d in e["decisions"])]
    sem = _block(judged) or {}
    sem.update({"judged": len(judged), "skipped": len(cur) - len(judged)})
    return {
        "window": {"from": iso(now - SUMMARY_WINDOW), "to": iso(now)},
        "total_overhead": _block([(e.get("latency_ms") or {}).get("total_overhead") for e in cur]),
        "upstream": _block([(e.get("latency_ms") or {}).get("upstream") for e in cur]),
        "per_control": {k: _block(v) for k, v in sorted(per.items())},
        "semantic_judge": sem,
    }


WINDOW_LEN = {"minute": timedelta(minutes=1), "hour": timedelta(hours=1), "day": timedelta(days=1)}


def budgets(events, now: datetime):
    out = []
    req = [e for e in events if e.get("type") == "request"]
    for ident_id, role, _p, _w, _m in IDENTITIES:
        bname = ROLE_BUDGET[role]
        b = BUDGETS[bname]
        window = b.get("window", "day")
        wl = WINDOW_LEN[window]
        wstart = datetime.fromtimestamp((now.timestamp() // wl.total_seconds()) * wl.total_seconds(), tz=timezone.utc)
        mine = [e for e in req if e.get("identity") == ident_id and parse_iso(e["ts"]) >= wstart]
        last_min = [e for e in req if e.get("identity") == ident_id and parse_iso(e["ts"]) > now - timedelta(minutes=1)]
        tool_sessions = Counter(e.get("session_id") for e in mine if e.get("endpoint") in ("tool_invoke", "mcp"))
        usage = {
            "tokens": sum((e.get("usage") or {}).get("prompt_tokens", 0) + (e.get("usage") or {}).get("completion_tokens", 0) for e in mine),
            "cost_usd": round(sum((e.get("usage") or {}).get("cost_usd", 0) for e in mine), 6),
            "compute_seconds": round(sum((e.get("usage") or {}).get("compute_seconds", 0) for e in mine), 2),
            "requests_per_minute": len(last_min),
            "tool_calls_per_session": max(tool_sessions.values()) if tool_sessions else 0,
        }
        limits = {k: b.get(k) for k in ("max_tokens", "max_cost_usd", "max_compute_seconds", "max_requests_per_minute", "max_tool_calls_per_session")}
        out.append({"identity": ident_id, "role": role, "budget": bname, "window": window if b else None,
                    "window_started_at": iso(wstart) if b else None, "resets_at": iso(wstart + wl) if b else None,
                    "on_exceed": b.get("on_exceed"), "usage": usage, "limits": limits})
    return {"identities": out}


def threat_catalog():
    return [{"id": t, "title": title, "owasp": ow, "atlas": at} for t, title, ow, at in THREATS]


def _tests_for(cid):
    h = int(hashlib.sha1(cid.encode()).hexdigest(), 16)
    neg, pos, edge = 3 + h % 5, 3 + (h >> 4) % 4, 2 + (h >> 8) % 2
    if cid in ("C-DELEG", "C-SUPPLY"):
        neg, pos, edge = 1, 1, 0
    if cid == "C-MEM-ACL":
        neg, pos, edge = 2, 1, 1
    return neg, pos, edge


def controls_payload():
    rows = []
    for cid, key, name, stages, threats, prio, tier, typ, levels, enabled, mode in CONTROLS:
        neg, pos, edge = _tests_for(cid)
        by_threat = {t: neg + pos + edge for t in threats}
        if cid == "C-INJ-PAT":
            by_threat = {"TH-01": 9, "TH-02": 5}
        if cid == "C-INJ-SEM":
            by_threat = {"TH-01": 6, "TH-02": 2}
        rows.append({"id": cid, "key": key, "name": name, "enabled": enabled, "mode": mode, "stages": stages, "priority": prio, "tier": tier,
                     "type": typ, "threat_ids": threats, "on_error": "fail_open" if cid == JUDGE else "fail_closed", "levels": levels,
                     "tests": {"total": neg + pos + edge, "negative": neg, "positive": pos, "edge": edge, "by_threat": by_threat}})
    return {"active_profile": "balanced", "controls": rows, "threats": threat_catalog()}


def policy_payload(now: datetime):
    return {
        "policy_version": POLICY_V_NEW, "feed_version": FEED_V_NEW, "loaded_at": iso(POLICY_CHANGE_AT), "last_reload_result": "ok",
        "policy": {
            "version": 1, "meta": {"name": "default-policy", "description": "Sample policy, 3 strictness levels (DEMO)"},
            "active_profile": "balanced", "mode": "enforce", "evaluation": "first_block", "on_error_default": "fail_closed",
            "identities": [{"id": i[0], "role": i[1], "profile": i[2]} for i in IDENTITIES],
            "budgets": BUDGETS,
            "controls": {c[1] or c[0].lower(): {"id": c[0], "enabled": c[9], "threat_ids": c[4], "stages": c[3], "levels": c[8], **({"mode": c[10]} if c[10] else {})} for c in CONTROLS},
            "semantic": {"provider": "ollama", "model": "<TBD-small-model>", "timeout_ms": 1500, "run_when": {"untrusted_segments": True, "risk_between": [0.15, 0.85], "sample_rate": 0.0}},
            "signature_feeds": [{"name": "historical-attacks", "path": "./feeds/attacks.yaml", "refresh_seconds": 30, "on_unavailable": "keep_last_good"}],
            "audit": {"path": "./data/audit.jsonl", "content": "masked", "max_event_bytes": 65536},
        },
    }


def health_payload():
    return {"status": "ok", "policy_version": POLICY_V_NEW, "feed_version": FEED_V_NEW}


def test_report(now: datetime):
    per = {}
    coverage = []
    failures = []
    totals = Counter()
    for cid, _k, _n, _s, threats, *_ in CONTROLS:
        neg, pos, edge = _tests_for(cid)
        h = int(hashlib.sha1((cid + "det").encode()).hexdigest(), 16)
        missed = 1 if cid in ("C-INJ-SEM", "C-PII-IN") else 0
        fp = 1 if cid in ("C-INJ-PAT",) else 0
        if cid == "C-SUPPLY":
            missed = 0
        per[cid] = {"negatives": neg, "negatives_blocked": neg - missed, "positives": pos, "positives_blocked": fp,
                    "passed": neg + pos + edge - missed - fp, "failed": missed + fp,
                    "latency_p50_ms": round(CTL_BASE_MS.get(cid, 0.05) * (1 if cid != JUDGE else 1.1), 3),
                    "latency_p95_ms": round(CTL_BASE_MS.get(cid, 0.05) * (2.4 + (h % 7) / 10), 3)}
        totals["passed"] += per[cid]["passed"]
        totals["failed"] += per[cid]["failed"]
        totals["negatives"] += neg
        totals["negatives_blocked"] += neg - missed
        totals["positives"] += pos
        totals["positives_blocked"] += fp
        n = 0
        for kind, count in (("negative", neg), ("positive", pos), ("edge", edge)):
            for i in range(count):
                n += 1
                coverage.append({"test_id": f"{cid.replace('C-', '')}-{n:03d}", "control_id": cid, "threat_id": threats[i % len(threats)], "kind": kind})
        if missed:
            failures.append({"id": f"{cid.replace('C-', '')}-E01", "title": "Base64-wrapped Polish paraphrase not stopped" if cid == JUDGE else "PESEL split across two messages not detected",
                             "kind": "edge", "controls": [cid], "threats": threats[:1], "expected": {"action": "block" if cid == JUDGE else "redact"},
                             "actual": {"action": "allow"}, "message": "expected action differs"})
        if fp:
            failures.append({"id": "INJ-P07", "title": "Benign 'ignore previous formatting' request blocked", "kind": "positive", "controls": [cid], "threats": ["TH-01"],
                             "expected": {"status": 200, "action": "allow"}, "actual": {"status": 403, "action": "block"}, "message": "false positive"})
    skipped = 4  # tests marked `live` (need Ollama) are skipped in the default run
    return {
        "generated_at": iso(now - timedelta(minutes=42)), "duration_seconds": 38.6, "status": "failed" if totals["failed"] else "passed",
        "policy_version": POLICY_V_NEW,
        "totals": {"total": totals["passed"] + totals["failed"] + skipped, "passed": totals["passed"], "failed": totals["failed"], "skipped": skipped},
        "overall": {k: totals[k] for k in ("negatives", "negatives_blocked", "positives", "positives_blocked")},
        "overhead": {"p50": 1.84, "p95": 6.37},
        "per_control": per, "coverage": coverage, "failures": failures,
    }


def fuzz_report(now: datetime):
    strategies = ["base64", "hex", "rot13", "zero_width", "homoglyph", "leetspeak", "roleplay", "split_messages", "html_comment", "translation_pl", "translation_de", "translation_es"]
    bypass_by_strategy = {"base64": 1, "hex": 0, "rot13": 2, "zero_width": 0, "homoglyph": 3, "leetspeak": 4, "roleplay": 9, "split_messages": 7, "html_comment": 2, "translation_pl": 6, "translation_de": 4, "translation_es": 3}
    per_ctl = {"C-INJ-PAT": (360, 31), "C-INJ-SEM": (360, 12), "C-SIG": (240, 18), "C-PII-OUT": (180, 5), "C-SECRET-OUT": (180, 2), "C-CODE-EXEC": (120, 3)}
    return {
        "generated_at": iso(now - timedelta(hours=2, minutes=10)), "label": "fuzz run against policy " + POLICY_V_NEW,
        "overall": {"attempts": sum(a for a, _ in per_ctl.values()), "bypasses": sum(b for _, b in per_ctl.values())},
        "per_control": {k: {"attempts": a, "bypasses": b} for k, (a, b) in per_ctl.items()},
        "per_strategy": {s: {"attempts": 120, "bypasses": bypass_by_strategy[s]} for s in strategies},
    }


# ---------------------------------------------------------------------------- time rebasing

TS_KEYS = {"ts", "generated_at", "loaded_at", "resets_at", "window_started_at", "from", "to", "since", "last_run"}


def rebase(obj, delta: timedelta):
    """Shifts every ISO timestamp under TS_KEYS by `delta` (keeps the demo 'live' relative to now)."""
    if isinstance(obj, list):
        return [rebase(x, delta) for x in obj]
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in TS_KEYS and isinstance(v, str) and v.endswith("Z"):
                try:
                    out[k] = iso(parse_iso(v) + delta)
                    continue
                except ValueError:
                    pass
            out[k] = rebase(v, delta)
        return out
    return obj

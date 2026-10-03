"""Admin telemetry and reporting endpoints (ARCHITECTURE.md §5.1, §8) for the dashboard.

Endpoints (all need an admin identity, see aicl/admin/policy.py):
  GET /admin/controls           controls with policy state, levels, threats and test coverage
  GET /admin/metrics/summary    counters by action/control/threat/OWASP/identity/severity, cost
  GET /admin/metrics/latency    p50/p95/p99 of overhead, upstream and each control
  GET /admin/metrics/budgets    usage vs limits per identity
  GET /admin/events             filtered audit events, newest first
  GET /admin/events/stream      live Server-Sent Events stream
  GET /admin/export/audit.jsonl full audit export
  GET /admin/reports/latest     last test-suite report (reports/test_report.json)
  GET /admin/reports/fuzz       last fuzzer report (reports/fuzz_*.json)

Payload shapes follow aicl/dashboard/README.md ("recommended" shapes); older keys are kept.
Metrics are computed from the audit log, so they survive a restart (§2). Parsed events are
cached until the audit file changes.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter, defaultdict
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from aicl import registry
from aicl.admin.policy import _require_admin
from aicl.audit import iter_events
from aicl.models import SEVERITY_RANK, AuditEvent
from aicl.runtime import Runtime
from aicl.state import window_bucket
from aicl.utils import utc_now_iso

REPO_ROOT = Path(__file__).resolve().parents[2]
_ACTING = ("block", "require_approval", "redact", "flag")


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None


def _threat_catalog(base: Path) -> dict[str, dict[str, Any]]:
    """catalog/threats.yaml -> {id: {...}} (OWASP LLM / Agentic / ATLAS refs)."""
    for root in (base, REPO_ROOT):
        data = _load_yaml(root / "catalog" / "threats.yaml")
        if isinstance(data, dict):
            return {t["id"]: t for t in data.get("threats", []) if isinstance(t, dict) and "id" in t}
    return {}


def _case_coverage(base: Path) -> dict[str, Counter[str]]:
    """Test cases per control and kind, from tests/cases/*.yaml (§5.1 'test coverage counts')."""
    out: dict[str, Counter[str]] = defaultdict(Counter)
    for root in (base, REPO_ROOT):
        cases_dir = root / "tests" / "cases"
        if not cases_dir.is_dir():
            continue
        for f in sorted(cases_dir.glob("*.yaml")):
            if f.name.startswith("attacks_seed"):
                continue
            for case in _load_yaml(f) or []:
                if isinstance(case, dict):
                    for cid in case.get("controls", []):
                        out[cid][str(case.get("kind", "other"))] += 1
        break
    return out


def _percentiles(values: list[float]) -> dict[str, Any]:
    def pct(q: float) -> float | None:
        if not values:
            return None
        v = sorted(values)
        return round(v[max(0, min(len(v) - 1, round(q / 100 * (len(v) - 1))))], 3)

    return {"p50": pct(50), "p95": pct(95), "p99": pct(99), "count": len(values)}


class _EventCache:
    """Audit events from disk plus not-yet-flushed ones, re-parsed only when the file changes."""

    def __init__(self, rt: Runtime):
        self.rt = rt
        self._sig: tuple[int, int] | None = None
        self._disk: list[AuditEvent] = []

    def all(self) -> list[AuditEvent]:
        path = self.rt.audit.path
        try:
            st = path.stat()
            sig: tuple[int, int] | None = (st.st_mtime_ns, st.st_size)
        except OSError:
            sig = None
        if sig != self._sig:
            self._disk = list(iter_events(path)) if sig else []
            self._sig = sig
        known = {e.event_id for e in self._disk}
        return self._disk + [e for e in self.rt.audit.recent_events() if e.event_id not in known]


def _acting(e: AuditEvent) -> list[Any]:
    return [d for d in e.decisions if d.action.value in _ACTING and not d.skipped]


def router(rt: Runtime) -> APIRouter:
    r = APIRouter(prefix="/admin")
    base = Path(rt.feeds.base_dir)
    catalog = _threat_catalog(base)
    events_cache = _EventCache(rt)

    def guard(request: Request) -> JSONResponse | None:
        return _require_admin(rt, {k.lower(): v for k, v in request.headers.items()})

    def catalog_list() -> list[dict[str, Any]]:
        return [
            {
                "id": tid,
                "title": t.get("name"),
                "category": t.get("category"),
                "owasp": t.get("owasp_llm", []),
                "owasp_agentic": t.get("owasp_agentic", []),
                "atlas": t.get("atlas", []),
            }
            for tid, t in sorted(catalog.items())
        ]

    @r.get("/controls")
    async def get_controls(request: Request) -> JSONResponse:
        """Every registered control with its policy entry. A control without an entry is disabled (§6.3)."""
        if (denied := guard(request)) is not None:
            return denied
        policy = rt.policy
        profile = policy.raw.active_profile
        coverage = _case_coverage(base)
        out = []
        for cid, ctrl in sorted(registry.all_controls().items()):
            spec = policy.control_spec(cid)
            key = next((k for k, s in policy.raw.controls.items() if s.id == cid), None)
            levels = (
                {p: lvl.model_dump(mode="json") for p, lvl in spec.levels.items()} if spec is not None else {}
            )
            cases = coverage.get(cid, Counter())
            out.append(
                {
                    "id": cid,
                    "key": key,
                    "name": key or type(ctrl).__name__,
                    "enabled": bool(spec and spec.enabled),
                    "in_policy": spec is not None,
                    "mode": (spec.mode if spec and spec.mode else policy.raw.mode),
                    "on_error": (spec.on_error if spec and spec.on_error else policy.raw.on_error_default),
                    "stages": [s.value for s in (spec.stages if spec and spec.stages else ctrl.stages)],
                    "priority": ctrl.priority,
                    "type": "semantic" if ctrl.priority >= 500 else "deterministic",
                    "threat_ids": list(spec.threat_ids) if spec else [],
                    "params": dict(spec.params) if spec else {},
                    "levels": levels,
                    "active_level": levels.get(profile, {}),
                    "tests": {
                        "total": sum(cases.values()),
                        "negative": cases.get("negative", 0),
                        "positive": cases.get("positive", 0),
                        "edge": cases.get("edge", 0),
                    },
                }
            )
        return JSONResponse({"active_profile": profile, "controls": out, "threats": catalog_list()})

    @r.get("/metrics/summary")
    async def metrics_summary(request: Request) -> JSONResponse:
        """Counters over the whole audit log (the dashboard derives short ranges from events)."""
        if (denied := guard(request)) is not None:
            return denied
        events = events_cache.all()
        requests = [e for e in events if e.type == "request"]

        by_action: Counter[str] = Counter()
        by_control: Counter[str] = Counter()
        by_threat: Counter[str] = Counter()
        by_owasp: Counter[str] = Counter()
        by_atlas: Counter[str] = Counter()
        by_identity: Counter[str] = Counter()
        by_endpoint: Counter[str] = Counter()
        by_severity: Counter[str] = Counter()
        cost = 0.0
        judged = skipped = 0

        for e in requests:
            by_action[e.final_action.value if e.final_action else "error"] += 1
            if e.identity:
                by_identity[e.identity] += 1
            if e.endpoint:
                by_endpoint[e.endpoint] += 1
            if e.usage:
                cost += e.usage.cost_usd
            acting = _acting(e)
            if acting:
                by_severity[max((d.severity for d in acting), key=lambda s: SEVERITY_RANK.get(s, 0))] += 1
            for d in acting:
                by_control[d.control_id] += 1
                for tid in d.threat_ids:
                    by_threat[tid] += 1
                    for ow in catalog.get(tid, {}).get("owasp_llm", []):
                        by_owasp[ow] += 1
                    for at in catalog.get(tid, {}).get("atlas", []):
                        by_atlas[at] += 1
            for d in e.decisions:
                if d.control_id == "C-INJ-SEM":
                    if d.skipped:
                        skipped += 1
                    else:
                        judged += 1

        return JSONResponse(
            {
                "security_posture": {
                    "active_profile": rt.policy.raw.active_profile,
                    "mode": rt.policy.raw.mode,
                    "policy_version": rt.policy.version,
                    "feed_version": rt.feeds.current().version,
                    "controls_loaded": len(
                        rt.controls if rt.controls is not None else registry.all_controls()
                    ),
                    "controls_enabled": sum(1 for s in rt.policy.controls.values() if s.enabled),
                },
                "totals": {
                    "requests": len(requests),
                    "blocked": by_action["block"],
                    "redacted": by_action["redact"],
                    "allowed": by_action["allow"] + by_action["flag"],
                },
                "requests_total": len(requests),
                "window": {"from": requests[0].ts if requests else None, "to": utc_now_iso()},
                "cost_usd": round(cost, 6),
                "semantic": {"judged": judged, "skipped": skipped},
                "by_action": dict(by_action),
                "by_control": dict(by_control),
                "by_threat": dict(by_threat),
                "by_owasp": dict(by_owasp),
                "by_owasp_llm": dict(by_owasp),
                "by_atlas": dict(by_atlas),
                "by_identity": dict(by_identity),
                "by_endpoint": dict(by_endpoint),
                "by_severity": dict(by_severity),
                "threat_catalog": catalog_list(),
            }
        )

    @r.get("/metrics/latency")
    async def metrics_latency(request: Request) -> JSONResponse:
        """p50/p95/p99 of the gateway overhead, the upstream call and every control."""
        if (denied := guard(request)) is not None:
            return denied
        overhead: list[float] = []
        upstream: list[float] = []
        per_control: dict[str, list[float]] = defaultdict(list)
        for e in events_cache.all():
            if e.latency_ms is None:
                continue
            overhead.append(e.latency_ms.total_overhead)
            if e.upstream_called:
                upstream.append(e.latency_ms.upstream)
            for cid, ms in e.latency_ms.per_control.items():
                per_control[cid].append(ms)
        overhead_p, upstream_p = _percentiles(overhead), _percentiles(upstream)
        return JSONResponse(
            {
                "total_overhead": overhead_p,
                "upstream": upstream_p,
                "total_overhead_ms": overhead_p,
                "upstream_ms": upstream_p,
                "per_control": {cid: _percentiles(v) for cid, v in sorted(per_control.items())},
                "target_p95_ms": 20,
            }
        )

    @r.get("/metrics/budgets")
    async def metrics_budgets(request: Request) -> JSONResponse:
        """Usage vs limits per identity, in the current window of its role's budget."""
        if (denied := guard(request)) is not None:
            return denied
        policy = rt.policy
        identities = []
        for ident in policy.raw.identities:
            budget = policy.budget_for(ident.role)
            role = policy.role(ident.role)
            window = budget.window if budget else "day"
            usage = await rt.state.get_usage(ident.id, window)
            minute = await rt.state.get_usage(ident.id, "minute")
            _bucket, resets_at = window_bucket(window)
            identities.append(
                {
                    "identity": ident.id,
                    "role": ident.role,
                    "budget": role.budget if role else None,
                    "window": window,
                    "window_started_at": _iso(resets_at - _WINDOW_SECONDS[window]),
                    "resets_at": _iso(resets_at),
                    "on_exceed": budget.on_exceed if budget else None,
                    "usage": {
                        "tokens": usage.tokens,
                        "cost_usd": round(usage.cost_usd, 6),
                        "compute_seconds": round(usage.compute_seconds, 3),
                        "requests": usage.requests,
                        "requests_per_minute": minute.requests,
                    },
                    "limits": {
                        "max_tokens": budget.max_tokens if budget else None,
                        "max_cost_usd": budget.max_cost_usd if budget else None,
                        "max_compute_seconds": budget.max_compute_seconds if budget else None,
                        "max_requests_per_minute": budget.max_requests_per_minute if budget else None,
                        "max_tool_calls_per_session": budget.max_tool_calls_per_session if budget else None,
                    },
                }
            )
        active_usage = [
            {
                "identity": identity,
                "bucket": bucket,
                "requests": c.requests,
                "prompt_tokens": c.prompt_tokens,
                "completion_tokens": c.completion_tokens,
                "total_tokens": c.tokens,
                "cost_usd": round(c.cost_usd, 6),
                "compute_seconds": c.compute_seconds,
            }
            for (identity, bucket), c in (await rt.state.all_usage()).items()
        ]
        roles = {name: role.model_dump(mode="json") for name, role in policy.raw.roles.items()}
        return JSONResponse({"identities": identities, "active_usage": active_usage, "roles": roles})

    @r.get("/events")
    async def get_events(
        request: Request,
        limit: int = Query(default=50, ge=1, le=5000),
        since: str | None = Query(default=None),
        action: str | None = Query(default=None),
        control: str | None = Query(default=None),
        identity: str | None = Query(default=None),
        endpoint: str | None = Query(default=None),
        type: str | None = Query(default=None),
    ) -> JSONResponse:
        """Filtered audit events, newest first."""
        if (denied := guard(request)) is not None:
            return denied
        since_norm = _norm_ts(since) if since else None
        out = []
        for e in reversed(events_cache.all()):
            if since_norm and e.ts < since_norm:
                continue
            if type and e.type != type:
                continue
            if action and (e.final_action is None or e.final_action.value != action):
                continue
            if identity and e.identity != identity:
                continue
            if endpoint and e.endpoint != endpoint:
                continue
            if control and not any(d.control_id == control for d in e.decisions):
                continue
            out.append(e.model_dump(mode="json"))
            if len(out) >= limit:
                break
        return JSONResponse({"total_found": len(out), "events": out})

    @r.get("/events/stream")
    async def events_stream(request: Request) -> Response:
        """Live Server-Sent Events stream of audit events (for clients that can send the auth header)."""
        if (denied := guard(request)) is not None:
            return denied
        queue: asyncio.Queue[AuditEvent] = asyncio.Queue(maxsize=1000)

        def on_event(ev: AuditEvent) -> None:
            if not queue.full():
                queue.put_nowait(ev)

        rt.audit.add_listener(on_event)

        async def sse() -> AsyncIterator[str]:
            try:
                yield ": connected to aicl audit event stream\n\n"
                while not await request.is_disconnected():
                    try:
                        ev = await asyncio.wait_for(queue.get(), timeout=15.0)
                        yield f"event: audit\ndata: {json.dumps(ev.model_dump(mode='json'), ensure_ascii=False)}\n\n"
                    except TimeoutError:
                        yield ": ping\n\n"
            finally:
                rt.audit.remove_listener(on_event)

        return StreamingResponse(sse(), media_type="text/event-stream")

    @r.get("/export/audit.jsonl")
    async def export_audit(request: Request) -> Response:
        if (denied := guard(request)) is not None:
            return denied
        if not rt.audit.path.exists():
            return Response(content="", media_type="application/x-ndjson")
        return FileResponse(
            path=str(rt.audit.path), filename="audit.jsonl", media_type="application/x-ndjson"
        )

    @r.get("/reports/latest")
    async def latest_report(request: Request) -> JSONResponse:
        """Last test-suite report (tests/harness/report.py), with the aliases the dashboard reads."""
        if (denied := guard(request)) is not None:
            return denied
        data = _read_json(_reports_dir(base) / "test_report.json")
        if data is None:
            return JSONResponse({"status": "no_report_available"}, status_code=404)
        return JSONResponse(_test_report_view(data))

    @r.get("/reports/fuzz")
    async def fuzz_report(request: Request) -> JSONResponse:
        """Last fuzzer report (tests/fuzz/run.py writes reports/fuzz_<timestamp>.json)."""
        if (denied := guard(request)) is not None:
            return denied
        files = sorted(_reports_dir(base).glob("fuzz_*.json"), key=lambda p: p.stat().st_mtime)
        data = _read_json(files[-1]) if files else None
        if data is None:
            return JSONResponse({"status": "no_report_available"}, status_code=404)
        return JSONResponse(_fuzz_report_view(data))

    return r


_WINDOW_SECONDS = {"minute": 60, "hour": 3600, "day": 86400}


def _iso(epoch: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(epoch, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _norm_ts(ts: str) -> str:
    """Accept any ISO form; audit timestamps compare as text in the 'YYYY-MM-DDTHH:MM:SS.mmmZ' form."""
    from datetime import UTC, datetime

    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return ts
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _reports_dir(base: Path) -> Path:
    for root in (base, REPO_ROOT):
        if (root / "reports").is_dir():
            return root / "reports"
    return REPO_ROOT / "reports"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _test_report_view(data: Mapping[str, Any]) -> dict[str, Any]:
    """Keep the report as written and add the keys the dashboard normalizer looks for."""
    out = dict(data)
    totals = dict(data.get("totals") or {})
    totals.setdefault("total", totals.get("cases"))
    out["totals"] = totals
    out.setdefault("overhead", {"p50": totals.get("overhead_ms_p50"), "p95": totals.get("overhead_ms_p95")})
    out.setdefault(
        "per_control",
        {
            cid: {**c, "latency_p50_ms": c.get("latency_ms_p50"), "latency_p95_ms": c.get("latency_ms_p95")}
            for cid, c in (data.get("controls") or {}).items()
        },
    )
    out["failures"] = [
        {**f, "message": "; ".join(f.get("failures", []))[:500]} if isinstance(f, dict) else f
        for f in data.get("failures", [])
    ]
    return out


def _fuzz_report_view(data: Mapping[str, Any]) -> dict[str, Any]:
    """tests/fuzz/run.py uses {bypass, n, rate}; the dashboard reads {attempts, bypasses, bypass_rate}."""

    def block(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict):
            return {}
        return {
            k: {"attempts": v.get("n"), "bypasses": v.get("bypass"), "bypass_rate": v.get("rate")}
            for k, v in raw.items()
            if isinstance(v, dict)
        }

    return {
        "generated_at": data.get("generated_at"),
        "label": f"profile {data.get('profile')}, seed {data.get('rng_seed')}",
        "overall": {"attempts": data.get("total"), "bypasses": data.get("bypasses")},
        "per_control": block(data.get("by_control")),
        "per_strategy": block(data.get("by_strategy")),
    }

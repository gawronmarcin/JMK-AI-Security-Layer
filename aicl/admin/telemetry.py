"""Admin telemetry and reporting endpoints (ARCHITECTURE.md §5.1, §8).

Endpoints:
  GET /admin/controls        - Catalog of controls, active profiles, parameters and status
  GET /admin/metrics/summary - Counters: total, blocked, redacted by control, threat, OWASP, identity
  GET /admin/metrics/latency - Overhead and per-control latency percentiles (p50, p95, p99)
  GET /admin/metrics/budgets - Live token, cost, and request usage counters vs limits
  GET /admin/events          - Filtered historical audit events (JSON)
  GET /admin/events/stream   - Live Server-Sent Events (SSE) stream of audit events
  GET /admin/export/audit.jsonl - Full audit log download
  GET /admin/reports/latest  - Summary of the last test suite run (test_report.json)
"""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse

from aicl import registry
from aicl.admin.policy import _require_admin
from aicl.audit import iter_events
from aicl.models import AuditEvent
from aicl.runtime import Runtime


def _load_threat_catalog(base_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Loads threat catalog mappings (OWASP LLM, OWASP Agentic, MITRE ATLAS)."""
    search_dirs = [Path.cwd(), Path(__file__).resolve().parents[2]]
    if base_dir:
        search_dirs.insert(0, Path(base_dir))

    for d in search_dirs:
        cat_file = d / "catalog" / "threats.yaml"
        if cat_file.exists():
            try:
                data = yaml.safe_load(cat_file.read_text(encoding="utf-8")) or {}
                threat_list = data.get("threats", [])
                return {t["id"]: t for t in threat_list if "id" in t}
            except (OSError, yaml.YAMLError):
                return {}
    return {}


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = max(0, min(len(v) - 1, round(q / 100 * (len(v) - 1))))
    return round(v[k], 3)


def _all_events(rt: Runtime) -> list[AuditEvent]:
    disk_events = list(iter_events(rt.audit.path))
    known_ids = {e.event_id for e in disk_events}
    recent = getattr(rt.audit, "recent_events", list)()
    for ev in recent:
        if ev.event_id not in known_ids:
            disk_events.append(ev)
            known_ids.add(ev.event_id)
    return disk_events


def router(rt: Runtime) -> APIRouter:
    r = APIRouter(prefix="/admin")
    threat_catalog = _load_threat_catalog(getattr(rt.feeds, "base_dir", None))

    @r.get("/controls")
    async def get_controls(request: Request) -> JSONResponse:
        """List all discovered controls with policy status and profile configuration."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        all_discovered = registry.all_controls()
        policy_raw = rt.policy.raw
        policy_controls = getattr(policy_raw, "controls", {}) or {}
        active_profile = policy_raw.active_profile

        out = []
        for cid, ctrl in sorted(all_discovered.items()):
            cfg = policy_controls.get(cid)
            stages = [s.value for s in ctrl.stages]
            enabled = True
            threat_ids: list[str] = []
            levels = {}
            active_level = {}

            if cfg:
                enabled = getattr(cfg, "enabled", True)
                threat_ids = list(getattr(cfg, "threat_ids", []))
                cfg_levels = getattr(cfg, "levels", {})
                if hasattr(cfg_levels, "model_dump"):
                    levels = cfg_levels.model_dump(mode="json")
                elif isinstance(cfg_levels, dict):
                    levels = cfg_levels
                active_level = levels.get(active_profile, {})

            out.append({
                "id": cid,
                "name": ctrl.__class__.__name__,
                "stages": stages,
                "priority": ctrl.priority,
                "enabled": enabled,
                "threat_ids": threat_ids,
                "levels": levels,
                "active_level": active_level,
            })
        return JSONResponse({"active_profile": active_profile, "controls": out})

    @r.get("/metrics/summary")
    async def metrics_summary(request: Request) -> JSONResponse:
        """Aggregated counters: requests, blocks, redactions, by control, by threat, by OWASP."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        events = _all_events(rt)
        request_events = [e for e in events if e.type == "request"]

        by_action: dict[str, int] = defaultdict(int)
        by_control: dict[str, int] = defaultdict(int)
        by_threat: dict[str, int] = defaultdict(int)
        by_owasp: dict[str, int] = defaultdict(int)
        by_atlas: dict[str, int] = defaultdict(int)
        by_identity: dict[str, int] = defaultdict(int)
        by_endpoint: dict[str, int] = defaultdict(int)

        total_blocked = 0
        total_redacted = 0
        total_allowed = 0

        for e in request_events:
            action = e.final_action.value if e.final_action else "allow"
            by_action[action] += 1
            if action == "block":
                total_blocked += 1
            elif action == "redact":
                total_redacted += 1
            elif action in ("allow", "flag"):
                total_allowed += 1

            if e.identity:
                by_identity[e.identity] += 1
            if e.endpoint:
                by_endpoint[str(e.endpoint)] += 1

            for d in e.decisions:
                if d.action.value in ("block", "redact", "flag"):
                    by_control[d.control_id] += 1
                    for tid in d.threat_ids:
                        by_threat[tid] += 1
                        t_info = threat_catalog.get(tid, {})
                        for ow in t_info.get("owasp_llm", []):
                            by_owasp[ow] += 1
                        for at in t_info.get("atlas", []):
                            by_atlas[at] += 1

        return JSONResponse({
            "security_posture": {
                "active_profile": rt.policy.raw.active_profile,
                "mode": rt.policy.raw.mode,
                "policy_version": rt.policy.version,
                "feed_version": rt.feeds.current().version,
                "controls_loaded": len(rt.controls) if rt.controls is not None else len(registry.all_controls()),
            },
            "totals": {
                "requests": len(request_events),
                "blocked": total_blocked,
                "redacted": total_redacted,
                "allowed": total_allowed,
            },
            "by_action": dict(by_action),
            "by_control": dict(by_control),
            "by_threat": dict(by_threat),
            "by_owasp_llm": dict(by_owasp),
            "by_atlas": dict(by_atlas),
            "by_identity": dict(by_identity),
            "by_endpoint": dict(by_endpoint),
        })

    @r.get("/metrics/latency")
    async def metrics_latency(request: Request) -> JSONResponse:
        """p50/p95/p99 total overhead and per-control latency percentiles."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        events = _all_events(rt)
        overhead_vals: list[float] = []
        upstream_vals: list[float] = []
        per_ctrl_vals: dict[str, list[float]] = defaultdict(list)

        for e in events:
            if e.latency_ms:
                if e.latency_ms.total_overhead is not None:
                    overhead_vals.append(float(e.latency_ms.total_overhead))
                if e.latency_ms.upstream is not None:
                    upstream_vals.append(float(e.latency_ms.upstream))
                for cid, lat in e.latency_ms.per_control.items():
                    per_ctrl_vals[cid].append(float(lat))

        per_ctrl_percentiles = {}
        for cid, vals in per_ctrl_vals.items():
            per_ctrl_percentiles[cid] = {
                "p50": _percentile(vals, 50),
                "p95": _percentile(vals, 95),
                "p99": _percentile(vals, 99),
                "count": len(vals),
            }

        return JSONResponse({
            "total_overhead_ms": {
                "p50": _percentile(overhead_vals, 50),
                "p95": _percentile(overhead_vals, 95),
                "p99": _percentile(overhead_vals, 99),
                "count": len(overhead_vals),
            },
            "upstream_ms": {
                "p50": _percentile(upstream_vals, 50),
                "p95": _percentile(upstream_vals, 95),
                "p99": _percentile(upstream_vals, 99),
                "count": len(upstream_vals),
            },
            "per_control": per_ctrl_percentiles,
        })

    @r.get("/metrics/budgets")
    async def metrics_budgets(request: Request) -> JSONResponse:
        """Live budget counters vs configured limits."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        all_usage = await rt.state.all_usage()
        usage_list = []
        for (identity, bucket), counter in all_usage.items():
            usage_list.append({
                "identity": identity,
                "bucket": bucket,
                "requests": counter.requests,
                "prompt_tokens": counter.prompt_tokens,
                "completion_tokens": counter.completion_tokens,
                "total_tokens": counter.tokens,
                "cost_usd": round(counter.cost_usd, 5),
                "compute_seconds": counter.compute_seconds,
            })

        roles = rt.policy.raw.roles
        roles_dump = {
            r_name: role.model_dump(mode="json") if hasattr(role, "model_dump") else role
            for r_name, role in roles.items()
        }

        return JSONResponse({
            "active_usage": usage_list,
            "roles": roles_dump,
        })

    @r.get("/events")
    async def get_events(
        request: Request,
        limit: int = Query(default=50, ge=1, le=1000),
        since: str | None = Query(default=None),
        action: str | None = Query(default=None),
        control: str | None = Query(default=None),
        identity: str | None = Query(default=None),
        endpoint: str | None = Query(default=None),
    ) -> JSONResponse:
        """Filtered audit events (newest first)."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        events = _all_events(rt)
        events.reverse()  # Newest first

        filtered = []
        for e in events:
            if since and e.ts < since:
                continue
            if action and e.final_action and e.final_action.value != action:
                continue
            if identity and e.identity != identity:
                continue
            if endpoint and e.endpoint and str(e.endpoint) != endpoint:
                continue
            if control:
                matching_decision = any(d.control_id == control for d in e.decisions)
                if not matching_decision:
                    continue

            filtered.append(e.model_dump(mode="json"))
            if len(filtered) >= limit:
                break

        return JSONResponse({"total_found": len(filtered), "events": filtered})

    @r.get("/events/stream")
    async def events_stream(request: Request) -> Response:
        """Real-time Server-Sent Events stream for live dashboard consumption."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        queue: asyncio.Queue[AuditEvent] = asyncio.Queue()

        def on_event(ev: AuditEvent) -> None:
            queue.put_nowait(ev)

        rt.audit.add_listener(on_event)

        async def sse_generator() -> AsyncIterator[str]:
            try:
                # Connection established comment
                yield ": connected to aicl audit event stream\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        data = json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
                        yield f"event: audit\ndata: {data}\n\n"
                    except TimeoutError:
                        # Keep-alive ping
                        yield ": ping\n\n"
            finally:
                if on_event in rt.audit._listeners:
                    rt.audit._listeners.remove(on_event)

        return StreamingResponse(sse_generator(), media_type="text/event-stream")

    @r.get("/export/audit.jsonl")
    async def export_audit(request: Request) -> Response:
        """Full audit export as download."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        if not rt.audit.path.exists():
            return Response(content="", media_type="application/x-ndjson")

        return FileResponse(
            path=str(rt.audit.path),
            filename="audit.jsonl",
            media_type="application/x-ndjson",
        )

    @r.get("/reports/latest")
    async def latest_report(request: Request) -> JSONResponse:
        """Summary of the latest test-suite execution (for dashboard panel)."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied

        report_file = Path("reports/test_report.json")
        if not report_file.exists():
            report_file = Path(__file__).resolve().parents[2] / "reports" / "test_report.json"

        if report_file.exists():
            try:
                data = json.loads(report_file.read_text(encoding="utf-8"))
                return JSONResponse(data)
            except (OSError, json.JSONDecodeError):
                return JSONResponse({"status": "no_report_available"})
        return JSONResponse({"status": "no_report_available"})

    return r

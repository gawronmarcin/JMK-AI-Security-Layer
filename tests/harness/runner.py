"""Wykonanie jednego przypadku YAML (§11.3) na działającym gatewayu + sprawdzenie `expect`.

Najważniejsze decyzje:
  * Błędy asercji są ZBIERANE (nie przerywamy na pierwszym), żeby raport mówił
    od razu wszystko, co jest nie tak z przypadkiem.
  * `action` czytamy z nagłówka X-AICL-Action (CONTRACT §5.1).
  * `control_ids` / `threat_ids` = error.control_id z body ∪ decyzje z audytu
    (żeby dało się sprawdzić też `redact`/`flag`, które zwracają 200).
    Liczą się decyzje z action != allow, także shadow_suppressed (dla testów shadow).
  * `upstream_called` = czy cokolwiek poza sędzią semantycznym dostało żądanie
    (upstream LLM albo backend narzędzia) — z logów mocków (§11.4).
  * Każdy przypadek sprawdza też kontrakt odpowiedzi (§5.1, §5.3).
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from tests.harness.case_schema import CaseSpec, StepSpec
from tests.harness.gateway import GatewayHandle
from tests.payloads import artifacts

ENDPOINTS = {"chat": "/v1/chat/completions", "tool_invoke": "/v1/tools/invoke",
             "artifact_scan": "/v1/artifacts/scan"}

# §5.3 — mapowanie status -> error.type
ERROR_TYPES = {401: {"aicl_auth_failed"}, 403: {"aicl_blocked", "aicl_approval_required"},
               429: {"aicl_budget_exceeded"}, 400: {"aicl_bad_request"}, 502: {"aicl_upstream_error"}}
ERROR_TO_ACTION = {"aicl_blocked": "block", "aicl_approval_required": "require_approval",
                   "aicl_budget_exceeded": "block", "aicl_auth_failed": "block"}
STOPPING = {"block", "require_approval", "redact"}

ARTIFACT_UPLOAD = os.environ.get("AICL_TEST_ARTIFACT_UPLOAD", "multipart")  # multipart | raw


@dataclass
class StepOutcome:
    step: int
    rep: int
    status: int
    action: str | None
    control_ids: list[str]
    threat_ids: list[str]
    upstream_called: bool
    overhead_ms: float | None
    per_control_ms: dict[str, float]
    request_id: str | None
    failures: list[str] = field(default_factory=list)

    @property
    def stopped(self) -> bool:
        return (self.action in STOPPING) or self.status in (401, 403, 429)


@dataclass
class CaseOutcome:
    case: CaseSpec
    steps: list[StepOutcome] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0

    @property
    def failures(self) -> list[str]:
        out = [f"[step {s.step} rep {s.rep}] {f}" for s in self.steps for f in s.failures]
        return out + ([self.error] if self.error else [])

    @property
    def passed(self) -> bool:
        return not self.failures

    @property
    def stopped(self) -> bool:
        """Czy gateway zatrzymał/zredagował cokolwiek w tym przypadku (do DR/FPR)."""
        return any(s.stopped for s in self.steps)


def _auth_headers(handle: GatewayHandle, case: CaseSpec, step: StepSpec) -> dict[str, str]:
    req = step.request
    if req.auth == "none":
        return {}
    if req.auth == "invalid":
        return {"Authorization": "Bearer definitely-not-a-valid-key"}
    ident = req.identity or case.identity
    if not ident:
        return {}
    if ident not in handle.keys:
        raise KeyError(f"identity '{ident}' nie istnieje w polityce (dodaj ją w policy_overlay)")
    return {"Authorization": f"Bearer {handle.keys[ident]}"}


async def _send(handle: GatewayHandle, case: CaseSpec, step: StepSpec) -> httpx.Response:
    req = step.request
    headers = {**_auth_headers(handle, case, step), **req.headers}
    path = ENDPOINTS[req.endpoint]
    if req.endpoint == "artifact_scan":
        if req.artifact is None:
            raise ValueError("artifact_scan wymaga `request.artifact`")
        data, default_name = artifacts.build(req.artifact.generator, **req.artifact.params)
        name = req.artifact.filename or default_name
        if ARTIFACT_UPLOAD == "raw":
            headers.setdefault("Content-Type", "application/octet-stream")
            headers.setdefault("X-AICL-Filename", name)
            return await handle.client.post(path, content=data, headers=headers)
        return await handle.client.post(path, files={"file": (name, data, "application/octet-stream")},
                                        headers=headers)
    return await handle.client.post(path, json=req.body, headers=headers)


def _body_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def _response_text(resp: httpx.Response, body: Any) -> str:
    """Surowy tekst + ponowna serializacja bez escapowania (polskie znaki, \\u...)."""
    text = resp.text
    if body is not None:
        text += "\n" + json.dumps(body, ensure_ascii=False)
    return text


def _check_contract(resp: httpx.Response, body: Any, failures: list[str]) -> None:
    if not resp.headers.get("x-aicl-request-id"):
        failures.append("brak nagłówka X-AICL-Request-Id (§5.1)")
    if resp.status_code < 400 and not resp.headers.get("x-aicl-action"):
        failures.append("brak nagłówka X-AICL-Action przy odpowiedzi 2xx (§5.1)")
    if resp.status_code in ERROR_TYPES:
        err = (body or {}).get("error") if isinstance(body, dict) else None
        if not isinstance(err, dict):
            failures.append(f"status {resp.status_code} bez body {{'error': {{...}}}} (§5.3)")
            return
        if err.get("type") not in ERROR_TYPES[resp.status_code]:
            failures.append(f"error.type={err.get('type')!r} niezgodny ze statusem "
                            f"{resp.status_code} (§5.3)")
        for k in ("message", "request_id"):
            if k not in err:
                failures.append(f"error.{k} brak w body (§5.3)")


async def run_step(handle: GatewayHandle, case: CaseSpec, step: StepSpec, idx: int, rep: int) -> StepOutcome:
    exp = step.expect
    await handle.reset_mocks()
    resp = await _send(handle, case, step)
    body = _body_json(resp)
    failures: list[str] = []
    _check_contract(resp, body, failures)

    request_id = resp.headers.get("x-aicl-request-id")
    action = resp.headers.get("x-aicl-action")
    err = body.get("error") if isinstance(body, dict) and isinstance(body.get("error"), dict) else {}
    if not action and err:
        action = ERROR_TO_ACTION.get(err.get("type"))

    need_audit = exp.control_ids is not None or exp.threat_ids is not None
    audit = await handle.audit_for(request_id, timeout=2.0 if need_audit else 0.3)
    control_ids: set[str] = set()
    threat_ids: set[str] = set()
    per_control: dict[str, float] = {}
    if err.get("control_id"):
        control_ids.add(err["control_id"])
    threat_ids.update(err.get("threat_ids") or [])
    if audit:
        for d in audit.get("decisions", []):
            if d.get("action") not in (None, "allow") and not d.get("skipped"):
                control_ids.add(d.get("control_id"))
                threat_ids.update(d.get("threat_ids") or [])
        per_control = dict((audit.get("latency_ms") or {}).get("per_control") or {})

    calls = await handle.downstream_calls()
    upstream_called = bool(calls["upstream"] or calls["tools"])
    overhead = resp.headers.get("x-aicl-overhead-ms")
    overhead_ms = float(overhead) if overhead not in (None, "") else None

    # ------------------------------------------------------------ asercje expect
    if exp.status is not None and resp.status_code != exp.status:
        failures.append(f"status {resp.status_code} != oczekiwany {exp.status}; body={resp.text[:300]}")
    if exp.action is not None and action != exp.action:
        failures.append(f"action {action!r} != oczekiwana {exp.action!r}")
    if exp.control_ids is not None:
        if audit is None and not err.get("control_id"):
            failures.append("nie znaleziono zdarzenia audytu dla request_id — nie da się sprawdzić control_ids")
        missing = set(exp.control_ids) - control_ids
        if missing:
            failures.append(f"nie zadziałały kontrole {sorted(missing)}; zadziałały {sorted(control_ids)}")
    if exp.threat_ids is not None:
        missing = set(exp.threat_ids) - threat_ids
        if missing:
            failures.append(f"brak threat_ids {sorted(missing)}; są {sorted(threat_ids)}")
    if exp.upstream_called is not None and upstream_called != exp.upstream_called:
        failures.append(f"upstream_called={upstream_called} != {exp.upstream_called} "
                        f"(upstream={len(calls['upstream'])}, tools={len(calls['tools'])})")
    text = _response_text(resp, body)
    for s in exp.response_contains or []:
        if s not in text:
            failures.append(f"odpowiedź nie zawiera {s!r}")
    for s in exp.response_not_contains or []:
        if s in text:
            failures.append(f"odpowiedź zawiera zakazany ciąg {s[:6]}… (wyciek!)")
    if exp.max_overhead_ms is not None:
        if overhead_ms is None:
            failures.append("brak X-AICL-Overhead-Ms, a przypadek wymaga max_overhead_ms")
        elif overhead_ms > exp.max_overhead_ms:
            failures.append(f"overhead {overhead_ms:.2f} ms > {exp.max_overhead_ms} ms")

    return StepOutcome(step=idx, rep=rep, status=resp.status_code, action=action,
                       control_ids=sorted(control_ids), threat_ids=sorted(threat_ids),
                       upstream_called=upstream_called, overhead_ms=overhead_ms,
                       per_control_ms=per_control, request_id=request_id, failures=failures)


async def run_case(handle: GatewayHandle, case: CaseSpec) -> CaseOutcome:
    out = CaseOutcome(case=case)
    t0 = time.perf_counter()
    try:
        for i, step in enumerate(case.steps, start=1):
            for rep in range(1, step.repeat + 1):
                out.steps.append(await run_step(handle, case, step, i, rep))
    except Exception as e:  # błąd harnessu/gatewaya, nie asercja
        out.error = f"{type(e).__name__}: {e}"
    out.duration_s = time.perf_counter() - t0
    return out

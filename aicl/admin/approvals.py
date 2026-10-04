"""Admin Human-in-the-Loop (HITL) approval endpoints.

Allows viewing pending approvals and approving or rejecting high-risk operations.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from aicl.approvals import ApprovalRequest
from aicl.audit import new_event
from aicl.errors import GatewayError
from aicl.flows.common import authenticate
from aicl.models import ErrorType
from aicl.runtime import Runtime

ADMIN_ROLE = "admin"


def _admin(rt: Runtime, headers: Mapping[str, str]) -> tuple[str | None, JSONResponse | None]:
    """-> (admin identity id, None) or (None, error response)."""
    if rt.env.get("AICL_ADMIN_OPEN") == "1":
        return "admin-open", None
    try:
        identity = authenticate(rt.policy, headers)
    except GatewayError as exc:
        return None, JSONResponse(exc.body(None).model_dump(mode="json"), status_code=exc.status)
    if identity.role != ADMIN_ROLE:
        err = GatewayError(ErrorType.blocked, "admin role required")
        return None, JSONResponse(err.body(None).model_dump(mode="json"), status_code=err.status)
    return identity.id, None


def _require_admin(rt: Runtime, headers: Mapping[str, str]) -> JSONResponse | None:
    return _admin(rt, headers)[1]


def _audit_decision(rt: Runtime, item: ApprovalRequest, admin_id: str) -> None:
    rt.audit.emit(new_event(
        "approval.decided", request_id=item.request_id, session_id=item.session_id, identity=admin_id,
        role=ADMIN_ROLE, policy_version=rt.policy.version,
        detail={"approval_id": item.approval_id, "status": item.status, "control_id": item.control_id,
                "requested_by": item.identity, "fingerprint": item.fingerprint},
    ))


def router(rt: Runtime) -> APIRouter:
    r = APIRouter(prefix="/admin/approvals")

    @r.get("")
    @r.get("/")
    async def list_approvals(
        request: Request,
        status: str = Query("all", description="Filter by status: pending, approved, rejected, all"),
    ) -> JSONResponse:
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        items = rt.approvals.list(status=status)
        return JSONResponse({"approvals": [i.model_dump(mode="json") for i in items], "count": len(items)})

    @r.get("/{approval_id}")
    async def get_approval(approval_id: str, request: Request) -> JSONResponse:
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        item = rt.approvals.get(approval_id)
        if item is None:
            return JSONResponse({"error": "approval not found"}, status_code=404)
        return JSONResponse(item.model_dump(mode="json"))

    @r.post("/{approval_id}/approve")
    async def approve_request(approval_id: str, request: Request) -> JSONResponse:
        headers = {k.lower(): v for k, v in request.headers.items()}
        admin_id, denied = _admin(rt, headers)
        if denied is not None:
            return denied
        assert admin_id is not None
        before = rt.approvals.get(approval_id)
        item = rt.approvals.approve(approval_id, decided_by=admin_id)
        if item is None:
            return JSONResponse({"error": "approval not found"}, status_code=404)
        if before is not None and before.status != "pending":
            return JSONResponse({"error": f"approval already {before.status}", "approval": item.model_dump(mode="json")},
                                status_code=409)
        _audit_decision(rt, item, admin_id)
        return JSONResponse({"status": "approved", "approval": item.model_dump(mode="json")})

    @r.post("/{approval_id}/reject")
    async def reject_request(approval_id: str, request: Request) -> JSONResponse:
        headers = {k.lower(): v for k, v in request.headers.items()}
        admin_id, denied = _admin(rt, headers)
        if denied is not None:
            return denied
        assert admin_id is not None
        before = rt.approvals.get(approval_id)
        item = rt.approvals.reject(approval_id, decided_by=admin_id)
        if item is None:
            return JSONResponse({"error": "approval not found"}, status_code=404)
        if before is not None and before.status != "pending":
            return JSONResponse({"error": f"approval already {before.status}", "approval": item.model_dump(mode="json")},
                                status_code=409)
        _audit_decision(rt, item, admin_id)
        return JSONResponse({"status": "rejected", "approval": item.model_dump(mode="json")})

    return r

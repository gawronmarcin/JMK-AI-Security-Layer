"""Admin Human-in-the-Loop (HITL) approval endpoints.

Allows viewing pending approvals and approving or rejecting high-risk operations.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from aicl.errors import GatewayError
from aicl.flows.common import authenticate
from aicl.models import ErrorType
from aicl.runtime import Runtime

ADMIN_ROLE = "admin"


def _require_admin(rt: Runtime, headers: Mapping[str, str]) -> JSONResponse | None:
    if rt.env.get("AICL_ADMIN_OPEN") == "1":
        return None
    try:
        identity = authenticate(rt.policy, headers)
    except GatewayError as exc:
        return JSONResponse(exc.body(None).model_dump(mode="json"), status_code=exc.status)
    if identity.role != ADMIN_ROLE:
        err = GatewayError(ErrorType.blocked, "admin role required")
        return JSONResponse(err.body(None).model_dump(mode="json"), status_code=err.status)
    return None


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
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        item = rt.approvals.approve(approval_id, decided_by="admin")
        if item is None:
            return JSONResponse({"error": "approval not found"}, status_code=404)
        return JSONResponse({"status": "approved", "approval": item.model_dump(mode="json")})

    @r.post("/{approval_id}/reject")
    async def reject_request(approval_id: str, request: Request) -> JSONResponse:
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        item = rt.approvals.reject(approval_id, decided_by="admin")
        if item is None:
            return JSONResponse({"error": "approval not found"}, status_code=404)
        return JSONResponse({"status": "rejected", "approval": item.model_dump(mode="json")})

    return r

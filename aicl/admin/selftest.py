"""Admin API for the live self-test (aicl/selftest.py).

    GET  /admin/selftest            probes + the expected outcome under the current policy
    POST /admin/selftest/run        run them (all, or ?ids=inj-direct,pii-in) -> report
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from aicl import selftest
from aicl.admin.policy import _require_admin
from aicl.runtime import Runtime


def _ids(ids: str | None) -> set[str] | None:
    return {i.strip() for i in ids.split(",") if i.strip()} if ids else None


def router(rt: Runtime) -> APIRouter:
    r = APIRouter(prefix="/admin/selftest")

    @r.get("")
    @r.get("/")
    async def probes(request: Request, ids: str | None = Query(None)) -> JSONResponse:
        if (denied := _require_admin(rt, {k.lower(): v for k, v in request.headers.items()})) is not None:
            return denied
        results = selftest.describe(rt, _ids(ids))
        return JSONResponse({"policy_version": rt.policy.version, "probes": [x.as_dict() for x in results]})

    @r.post("/run")
    async def run(request: Request, ids: str | None = Query(None)) -> JSONResponse:
        if (denied := _require_admin(rt, {k.lower(): v for k, v in request.headers.items()})) is not None:
            return denied
        return JSONResponse(await selftest.run(rt, _ids(ids)))

    return r

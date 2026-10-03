"""Admin policy endpoints (§5.1, GUIDANCE): validate a candidate policy, force a reload.

Admin endpoints need an identity with role `admin`. `AICL_ADMIN_OPEN=1` disables the
check for a local demo (§5.1); never set it on a gateway reachable from outside.
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from aicl.errors import GatewayError
from aicl.flows.common import authenticate
from aicl.models import ErrorType
from aicl.policy.loader import PolicyError, parse_policy
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
    r = APIRouter(prefix="/admin/policy")

    @r.post("/validate")
    async def validate(request: Request) -> JSONResponse:
        """Body: candidate policy YAML. Validates only, never applies."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        source = (await request.body()).decode("utf-8", errors="replace")
        try:
            candidate = parse_policy(source, rt.env)
        except PolicyError as exc:
            return JSONResponse({"valid": False, "errors": exc.errors}, status_code=400)
        return JSONResponse(
            {"valid": True, "policy_version": candidate.version, "warnings": list(candidate.warnings)}
        )

    @r.post("/reload")
    async def reload(request: Request) -> JSONResponse:
        """Reload the policy file now (the file watcher normally does this within ~1 s)."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        reloaded = rt.reload_policy(reason="manual")
        return JSONResponse({"reloaded": reloaded, "policy_version": rt.policy.version})

    return r

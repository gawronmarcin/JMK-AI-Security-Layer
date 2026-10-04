"""Admin policy endpoints (§5.1, GUIDANCE): validate a candidate policy, force a reload.

Admin endpoints need an identity with role `admin`. `AICL_ADMIN_OPEN=1` disables the
check for a local demo (§5.1); never set it on a gateway reachable from outside.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from aicl.errors import GatewayError
from aicl.flows.common import authenticate
from aicl.models import ErrorType
from aicl.policy.loader import PolicyError, parse_policy
from aicl.policy.preview import preview_policy_change
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

    @r.post("/preview")
    async def preview(
        request: Request,
        last_n: int = Query(50, description="Number of recent request events to replay"),
    ) -> JSONResponse:
        """Body: candidate policy YAML or JSON with policy + last_n. Replays recorded requests; returns diff."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        raw_body = (await request.body()).decode("utf-8", errors="replace")
        limit = last_n
        source = raw_body
        try:
            parsed_json = json.loads(raw_body)
            if isinstance(parsed_json, dict) and "policy" in parsed_json:
                source = str(parsed_json["policy"])
                if "last_n" in parsed_json:
                    limit = int(parsed_json["last_n"])
                elif "limit" in parsed_json:
                    limit = int(parsed_json["limit"])
        except ValueError:
            pass

        try:
            candidate = parse_policy(source, rt.env)
        except PolicyError as exc:
            return JSONResponse({"valid": False, "errors": exc.errors}, status_code=400)

        result = preview_policy_change(rt, candidate, limit=limit)
        return JSONResponse(result)

    @r.post("/reload")
    async def reload(request: Request) -> JSONResponse:
        """Reload the policy file now (the file watcher normally does this within ~1 s)."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        reloaded = rt.reload_policy(reason="manual")
        last = rt.last_reload
        rejected = last.get("result") == "rejected"
        return JSONResponse(
            {
                "ok": not rejected,
                "reloaded": reloaded,
                "result": last.get("result"),
                "errors": [last["error"]] if rejected and last.get("error") else [],
                "policy_version": rt.policy.version,
            }
        )

    @r.get("")
    @r.get("/")
    async def get_policy(request: Request) -> JSONResponse:
        """Active policy (secrets stripped) + version (§5.1)."""
        headers = {k.lower(): v for k, v in request.headers.items()}
        if (denied := _require_admin(rt, headers)) is not None:
            return denied
        raw = rt.policy.raw.model_dump(mode="json")
        for ident in raw.get("identities", []):
            if "api_key_env" in ident:
                ident["api_key_env"] = "[MASKED]"
        last = rt.last_reload
        return JSONResponse(
            {
                "version": rt.policy.version,
                "policy_version": rt.policy.version,
                "feed_version": rt.feeds.current().version,
                "loaded_at": last.get("at"),
                "last_reload_result": last.get("result"),
                "last_reload_error": last.get("error"),
                "policy": raw,
                "warnings": list(rt.policy.warnings),
            }
        )

    return r

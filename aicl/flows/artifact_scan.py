"""Flow for POST /v1/artifacts/scan (ARCHITECTURE.md §2, §5.1).

Contract notes:
- Stages: ingress → artifact → post
- Supports multipart/form-data upload (file parameter) and raw octet-stream upload
- Authenticates identity using Bearer token (C-AUTH)
- Applies ingress stage limits (e.g. C-SIZE)
- Applies Stage.artifact controls (C-ARTIFACT)
- Returns 200 on clean artifacts, 403 on blocked artifacts with standard error format
"""

from __future__ import annotations

from collections.abc import Mapping

from fastapi import Request

from aicl.engine import run_stage
from aicl.errors import GatewayError
from aicl.flows.common import (
    BodyReader,
    FlowResponse,
    RequestRecord,
    account_usage,
    stop_if_blocked,
)
from aicl.models import Origin, RequestContext, Segment, Stage
from aicl.runtime import Runtime


async def handle_artifact_scan(
    rt: Runtime, request: Request, read_body: BodyReader, headers: Mapping[str, str]
) -> FlowResponse:
    rec = RequestRecord(rt=rt, endpoint="artifact_scan", headers=headers)
    try:
        return await _run(rt, rec, request, read_body, headers)
    except GatewayError as exc:
        return rec.fail(exc)
    finally:
        await account_usage(rt, rec)


async def _run(
    rt: Runtime,
    rec: RequestRecord,
    request: Request,
    read_body: BodyReader,
    headers: Mapping[str, str],
) -> FlowResponse:
    policy = rec.policy
    identity = rec.authenticate()
    assert rec.profile is not None

    content_type = headers.get("content-type", "")
    data: bytes = b""
    filename: str = ""
    if content_type.startswith("multipart/form-data"):
        form = await request.form()
        upload = form.get("file")
        if not hasattr(upload, "read"):
            for v in form.values():
                if hasattr(v, "read"):
                    upload = v
                    break
        if hasattr(upload, "read"):
            data = await upload.read()
            filename = getattr(upload, "filename", None) or "artifact.bin"
        else:
            data = b""
            filename = "artifact.bin"
    else:
        data = await rec.read_body(read_body)
        filename = headers.get("x-aicl-filename", "artifact.bin")

    ctx = RequestContext(
        request_id=rec.request_id,
        session_id=rec.session_id,
        endpoint="artifact_scan",
        stage=Stage.ingress,
        identity=identity.id,
        role=identity.role,
        profile=rec.profile,
        model=None,
        segments=[
            Segment(
                idx=0,
                text=filename,
                norm=filename.casefold(),
                decoded=[],
                origin=Origin.artifact,
                trust="untrusted",
                meta={"filename": filename, "size": len(data)},
            )
        ],
        artifact=data,
        policy_version=policy.version,
    )

    # Ingress stage (size limits, etc.)
    stop_if_blocked(rec.add_stage(await run_stage(policy, ctx, Stage.ingress, rt.controls)))

    # Artifact stage (C-ARTIFACT)
    art_ctx = ctx.model_copy(update={"stage": Stage.artifact})
    result = rec.add_stage(await run_stage(policy, art_ctx, Stage.artifact, rt.controls))
    stop_if_blocked(result)

    final = rec.final_action()
    rec.emit(final)
    return FlowResponse(
        status=200,
        body={
            "status": "allowed",
            "verdict": "clean",
            "filename": filename,
            "size": len(data),
        },
        headers=rec.response_headers(final),
    )

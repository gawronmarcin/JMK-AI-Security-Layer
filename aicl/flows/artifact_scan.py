"""POST /v1/artifacts/scan (§1.2, §5.1):

    C-AUTH -> read upload (limited) -> ingress -> artifact -> post

Upload: multipart/form-data with a `file` part (default of the test harness), or the raw
bytes with an optional `X-AICL-Filename` header. Both paths read the body through the same
limit, C-SIZE `max_artifact_bytes`, before anything parses it; multipart is then parsed
from that buffer.

The verdict in a 200 response reflects the final action: `clean` (allow) or `flagged`
(warnings such as a raw pickle format, unknown globals or an extension mismatch).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from fastapi import Request
from starlette.datastructures import UploadFile

from aicl.engine import run_stage
from aicl.errors import GatewayError
from aicl.flows.common import (
    BodyReader,
    FlowResponse,
    RequestRecord,
    account_usage,
    stop_if_blocked,
)
from aicl.models import Action, ErrorType, Origin, RequestContext, Segment, Stage
from aicl.runtime import Runtime

ARTIFACT_CONTROL_ID = "C-ARTIFACT"
MULTIPART_SLACK = 64 * 1024  # boundaries and part headers around the file


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


async def _read_upload(
    rec: RequestRecord, request: Request, read_body: BodyReader, headers: Mapping[str, str]
) -> tuple[bytes, str]:
    if not headers.get("content-type", "").startswith("multipart/form-data"):
        data = await rec.read_body(read_body, "max_artifact_bytes")
        return data, headers.get("x-aicl-filename", "artifact.bin")

    body = await rec.read_body(read_body, "max_artifact_bytes", slack=MULTIPART_SLACK)

    async def replay() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    form = await Request(request.scope, replay).form(max_files=1, max_fields=10)
    upload = form.get("file")
    if not isinstance(upload, UploadFile):
        upload = next((v for v in form.values() if isinstance(v, UploadFile)), None)
    if upload is None:
        raise GatewayError(ErrorType.bad_request, "multipart upload without a file part")
    return await upload.read(), upload.filename or "artifact.bin"


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
    data, filename = await _read_upload(rec, request, read_body, headers)

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
                origin=Origin.artifact,
                trust="untrusted",
                meta={"filename": filename, "size": len(data)},
            )
        ],
        artifact=data,
        policy_version=policy.version,
    )

    stop_if_blocked(rec.add_stage(await run_stage(policy, ctx, Stage.ingress, rt.controls)), rec)
    art_ctx = ctx.model_copy(update={"stage": Stage.artifact})
    stop_if_blocked(rec.add_stage(await run_stage(policy, art_ctx, Stage.artifact, rt.controls)), rec)

    final = rec.final_action()
    rec.emit(final)
    findings = [m.kind for d in rec.decisions() if d.control_id == ARTIFACT_CONTROL_ID for m in d.matches]
    return FlowResponse(
        status=200,
        body={
            "verdict": "clean" if final == Action.allow else "flagged",
            "action": final.value,
            "filename": filename,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "findings": sorted(set(findings)),
        },
        headers=rec.response_headers(final),
    )

"""POST /v1/chat/completions (§1.2):

    C-AUTH -> ingress -> input -> upstream -> output (+ tool_call per proposed call) -> post

Each message becomes one segment with idx = message index; response choices get
idx = len(messages) + choice index, so audit segment_idx values never collide.

Provisional choices, to be confirmed with the detectors team:
  * tool-call arguments are not turned into segments yet (only ctx.tool / ctx.tool_args);
  * if any proposed tool call is blocked, the whole response is blocked;
  * non-text content parts (images, audio) are not inspected; their count goes to segment meta.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aicl.engine import run_stage
from aicl.errors import GatewayError
from aicl.flows.common import (
    BodyReader,
    FlowResponse,
    RequestRecord,
    account_usage,
    apply_redacted_args,
    extract_tool_arg_segments,
    stop_if_blocked,
)
from aicl.models import Action, ErrorType, Origin, RequestContext, Segment, Stage, Trust, Usage
from aicl.normalize import build_segment
from aicl.policy.schema import ModelSpec
from aicl.proxy import UpstreamError
from aicl.runtime import Runtime

_ROLE_ORIGIN = {
    "system": Origin.system,
    "developer": Origin.system,
    "user": Origin.user,
    "assistant": Origin.assistant,
    "tool": Origin.tool_result,
    "function": Origin.tool_result,
}


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str
    content: str | list[dict[str, Any]] | None = None


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str
    messages: list[ChatMessage] = Field(min_length=1)
    stream: bool = False


def _text_of(content: str | list[dict[str, Any]] | None) -> tuple[str, int]:
    """(text, number of non-text parts) for OpenAI string or content-part messages."""
    if content is None:
        return "", 0
    if isinstance(content, str):
        return content, 0
    texts = [p.get("text", "") for p in content if p.get("type") == "text"]
    return "\n".join(t for t in texts if isinstance(t, str)), sum(
        1 for p in content if p.get("type") != "text"
    )


def _input_segments(req: ChatRequest) -> list[Segment]:
    segments = []
    for i, msg in enumerate(req.messages):
        origin = _ROLE_ORIGIN.get(msg.role)
        if origin is None:
            raise GatewayError(ErrorType.bad_request, f"messages[{i}].role {msg.role!r} is not supported")
        text, non_text = _text_of(msg.content)
        meta = {"role": msg.role} | ({"non_text_parts": non_text} if non_text else {})
        trust: Trust = "untrusted" if origin == Origin.tool_result else "trusted"
        segments.append(build_segment(i, text, origin, trust, meta))
    return segments


def _parse(raw: bytes) -> tuple[ChatRequest, dict[str, Any]]:
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise GatewayError(ErrorType.bad_request, "body is not valid JSON") from exc
    if not isinstance(data, dict):
        raise GatewayError(ErrorType.bad_request, "body must be a JSON object")
    try:
        return ChatRequest.model_validate(data), data
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(p) for p in first["loc"])
        raise GatewayError(ErrorType.bad_request, f"{loc}: {first['msg']}") from exc


def _tool_calls(choice: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    calls = []
    for call in (choice.get("message") or {}).get("tool_calls") or []:
        fn = call.get("function") or {}
        name = fn.get("name")
        if not isinstance(name, str):
            raise UpstreamError("tool call without a function name")
        raw_args = fn.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
        except ValueError:
            args = {"_unparsed": raw_args}
        calls.append((name, args if isinstance(args, dict) else {"_value": args}))
    return calls


def _usage(
    model: ModelSpec, body: dict[str, Any], prompt_chars: int, completion_chars: int, upstream_ms: float
) -> Usage:
    raw = body.get("usage") or {}
    # No usage from the upstream: estimate ~4 characters per token (§5.5).
    prompt = int(raw.get("prompt_tokens") or prompt_chars // 4)
    completion = int(raw.get("completion_tokens") or completion_chars // 4)
    prices = model.price_per_1k_tokens
    return Usage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        cost_usd=round(prompt / 1000 * prices.input + completion / 1000 * prices.output, 8),
        compute_seconds=round(upstream_ms / 1000, 3) if model.local else 0.0,
    )


async def handle_chat(rt: Runtime, read_body: BodyReader, headers: Mapping[str, str]) -> FlowResponse:
    rec = RequestRecord(rt=rt, endpoint="chat", headers=headers)
    try:
        return await _run(rt, rec, read_body, headers)
    except GatewayError as exc:
        return rec.fail(exc)
    finally:
        await _account(rt, rec)


async def _run(
    rt: Runtime, rec: RequestRecord, read_body: BodyReader, headers: Mapping[str, str]
) -> FlowResponse:
    policy = rec.policy
    identity = rec.authenticate()
    req, data = _parse(await rec.read_body(read_body))
    rec.model = req.model
    segments = _input_segments(req)
    assert rec.profile is not None

    # §5.4: untrusted content (tool results) entering the session taints it; C-TAINT then
    # blocks privileged tool calls for the rest of the session.
    if any(s.trust == "untrusted" for s in segments):
        await rt.state.mark_tainted(rec.session_id, "tool_result")

    ctx = RequestContext(
        request_id=rec.request_id,
        session_id=rec.session_id,
        endpoint="chat",
        stage=Stage.ingress,
        identity=identity.id,
        role=identity.role,
        profile=rec.profile,
        model=req.model,
        segments=segments,
        tainted=(await rt.state.get_session(rec.session_id)).tainted,
        policy_version=policy.version,
    )

    stop_if_blocked(rec.add_stage(await run_stage(policy, ctx, Stage.ingress, rt.controls)), rec)

    model = policy.models.get(req.model)
    if model is None:
        raise GatewayError(ErrorType.bad_request, f"unknown model {req.model!r}")

    result = rec.add_stage(await run_stage(policy, ctx, Stage.input, rt.controls))
    stop_if_blocked(result, rec)
    if result.taints_session:
        await rt.state.mark_tainted(rec.session_id, "input")
    if result.action == Action.redact:
        for seg in result.segments:
            if seg.text != segments[seg.idx].text:
                data["messages"][seg.idx]["content"] = seg.text
    ctx = ctx.model_copy(update={"risk": result.risk})

    try:
        upstream = await rt.upstream.chat(model, {k: v for k, v in data.items() if k != "stream"}, headers)
    except UpstreamError as exc:
        raise GatewayError(ErrorType.upstream_error, str(exc)) from exc
    rec.upstream_called = True
    rec.upstream_ms = upstream.latency_ms
    body = upstream.body

    try:
        choices = [c for c in body["choices"] if isinstance(c, dict)]
        base = len(req.messages)
        out_segments = []
        for i, choice in enumerate(choices):
            text, _ = _text_of((choice.get("message") or {}).get("content"))
            out_segments.append(build_segment(base + i, text, Origin.assistant))
        proposed = [(i, call) for i, choice in enumerate(choices) for call in _tool_calls(choice)]
    except UpstreamError as exc:
        raise GatewayError(ErrorType.upstream_error, str(exc)) from exc

    rec.usage = _usage(
        model,
        body,
        prompt_chars=sum(len(s.text) for s in segments),
        completion_chars=sum(len(s.text) for s in out_segments),
        upstream_ms=upstream.latency_ms,
    )

    out_ctx = ctx.model_copy(update={"segments": out_segments})
    result = rec.add_stage(await run_stage(policy, out_ctx, Stage.output, rt.controls))
    stop_if_blocked(result, rec)
    if result.action == Action.redact:
        for seg in result.segments:
            choices[seg.idx - base].setdefault("message", {})["content"] = seg.text

    for choice_idx, (tool, args) in proposed:
        arg_segments = extract_tool_arg_segments(
            args, origin=Origin.assistant, base_idx=len(out_segments), tool_name=tool
        )
        if arg_segments:
            # Check proposed tool call arguments for output leaks (secrets/PII)
            out_arg_ctx = ctx.model_copy(update={"stage": Stage.output, "segments": arg_segments})
            out_arg_res = rec.add_stage(await run_stage(policy, out_arg_ctx, Stage.output, rt.controls))
            stop_if_blocked(out_arg_res, rec)
            if out_arg_res.action == Action.redact:
                args = apply_redacted_args(args, out_arg_res.segments)
                _update_choice_tool_call_args(choices[choice_idx], tool, args)

        call_ctx = ctx.model_copy(update={"stage": Stage.tool_call, "segments": arg_segments, "tool": tool, "tool_args": args})
        stop_if_blocked(rec.add_stage(await run_stage(policy, call_ctx, Stage.tool_call, rt.controls)), rec)

    final = rec.final_action()
    rec.emit(final)
    return FlowResponse(status=200, body=body, headers=rec.response_headers(final), stream=req.stream)


def _update_choice_tool_call_args(choice: dict[str, Any], tool: str, redacted_args: Any) -> None:
    msg = choice.get("message")
    if not isinstance(msg, dict):
        return
    for call in msg.get("tool_calls") or []:
        fn = call.get("function")
        if isinstance(fn, dict) and fn.get("name") == tool:
            fn["arguments"] = json.dumps(redacted_args, ensure_ascii=False)


_account = account_usage

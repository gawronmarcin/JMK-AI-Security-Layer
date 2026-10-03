"""Minimal OpenAI-compatible upstream for core tests only. R4 owns the real mock (tests/mocks).

X-Mock-Scenario: echo (default) | fixed:<text> | error:<status> | tool_call:<name>:<json args> | no_usage
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def make_fake_upstream() -> tuple[FastAPI, list[dict[str, Any]]]:
    app = FastAPI()
    calls: list[dict[str, Any]] = []

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> JSONResponse:
        body = await request.json()
        scenario = request.headers.get("x-mock-scenario", "echo")
        calls.append(
            {"body": body, "scenario": scenario, "authorization": request.headers.get("authorization")}
        )

        if scenario.startswith("error:"):
            return JSONResponse({"error": "boom"}, status_code=int(scenario.split(":", 1)[1]))

        message: dict[str, Any] = {"role": "assistant", "content": None}
        if scenario.startswith("fixed:"):
            message["content"] = scenario.split(":", 1)[1]
        elif scenario.startswith("tool_call:"):
            _, name, args = scenario.split(":", 2)
            message["tool_calls"] = [
                {"id": "call_1", "type": "function", "function": {"name": name, "arguments": args}}
            ]
        else:
            last_user = next((m for m in reversed(body["messages"]) if m["role"] == "user"), {"content": ""})
            message["content"] = last_user["content"]

        response: dict[str, Any] = {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "created": 0,
            "model": body["model"],
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        }
        if scenario != "no_usage":
            response["usage"] = {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
        return JSONResponse(response)

    return app, calls

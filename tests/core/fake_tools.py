"""Mock tool backend for testing (ARCHITECTURE.md §11.4).

Provides an ASGI FastAPI app that handles tool invocations for mock tool backends:
- search_docs
- fetch_url
- send_email
- run_shell

Respects X-Mock-Scenario headers (e.g. error:<status>, leak_secret, leak_pii, fixed:<text>).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

AWS_KEY = "AKIA" + "Z7Q2M4XK9P3L8W1N"


def make_mock_tools() -> tuple[FastAPI, list[dict[str, Any]]]:
    app = FastAPI()
    calls: list[dict[str, Any]] = []

    @app.post("/{tool_name:path}")
    async def invoke(tool_name: str, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except (ValueError, TypeError):
            body = {}
        scenario = request.headers.get("x-mock-scenario", "default")
        calls.append(
            {
                "tool": tool_name,
                "body": body,
                "scenario": scenario,
                "headers": dict(request.headers),
            }
        )

        if scenario.startswith("error:"):
            status = int(scenario.split(":", 1)[1])
            return JSONResponse({"error": f"mock tool error {status}"}, status_code=status)

        if scenario.startswith("fixed:"):
            return JSONResponse({"output": scenario.split(":", 1)[1]})

        if scenario == "leak_secret":
            return JSONResponse({"output": f"Here is the credential: {AWS_KEY}"})

        if scenario == "leak_pii":
            return JSONResponse({"output": "Customer contact: jan.kowalski@example.com, PESEL: 44051401458"})

        # Normal tool behaviour
        actual_tool = body.get("tool") or tool_name.strip("/")
        args = body.get("arguments") or {}

        if "search" in actual_tool:
            query = args.get("query", "")
            return JSONResponse({"output": f"Search results for: {query}"})
        if "fetch" in actual_tool:
            url = args.get("url", "")
            return JSONResponse({"output": f"Content from {url}"})
        if "email" in actual_tool:
            to = args.get("to", "")
            return JSONResponse({"output": f"Email successfully sent to {to}"})
        if "shell" in actual_tool:
            cmd = args.get("cmd", "")
            return JSONResponse({"output": f"Executed command: {cmd}"})

        return JSONResponse({"output": f"Tool {actual_tool} executed with {args}"})

    return app, calls

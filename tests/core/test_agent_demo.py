"""scripts/agent_demo.py: the agent loop through the real gateway, with a scripted model (no Ollama)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from policy_files import write_policy

from aicl.app import create_app
from tests.mocks.mock_tools import app as mock_tools_app

REPO = Path(__file__).parents[2]
_spec = importlib.util.spec_from_file_location("agent_demo", REPO / "scripts" / "agent_demo.py")
agent_demo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent_demo)

ENV = {
    "AICL_KEY_SUPPORT": "k-support", "AICL_KEY_RESEARCH": "k-research", "AICL_KEY_ADMIN": "k-admin",
    "AICL_UPSTREAM_MOCK_URL": "http://mock-llm/v1", "AICL_OLLAMA_URL": "http://mock-llm",
    "AICL_TOOL_DOCS_URL": "http://mock-tools/tools/search_docs", "AICL_TOOL_FETCH_URL": "http://mock-tools/tools/fetch_url",
    "AICL_TOOL_MAIL_URL": "http://mock-tools/tools/send_email", "AICL_TOOL_SHELL_URL": "http://mock-tools/tools/run_shell",
}


def scripted_model(turns: list[dict[str, Any]]) -> FastAPI:
    """An OpenAI-compatible model that answers with the given assistant messages, in order."""
    app = FastAPI()
    queue = list(turns)

    @app.post("/v1/chat/completions")
    async def chat(request: Request) -> JSONResponse:
        body = await request.json()
        msg = queue.pop(0) if queue else {"role": "assistant", "content": "done"}
        return JSONResponse({"id": "x", "object": "chat.completion", "created": 0, "model": body["model"],
                             "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}],
                             "usage": {"prompt_tokens": 10, "completion_tokens": 5}})

    return app


def call(name: str, args: dict, cid: str = "c1") -> dict[str, Any]:
    return {"role": "assistant", "content": None,
            "tool_calls": [{"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


class Router(httpx.AsyncBaseTransport):
    def __init__(self, routes):
        self.routes = routes

    async def handle_async_request(self, request):
        return await self.routes[request.url.host].handle_async_request(request)


async def _agent(tmp_path, turns, scenario, model="mock-commercial"):
    router = Router({"mock-llm": httpx.ASGITransport(scripted_model(turns)),
                     "mock-tools": httpx.ASGITransport(mock_tools_app)})
    app = create_app(write_policy(tmp_path), env=ENV, base_dir=REPO, audit_path=tmp_path / "audit.jsonl",
                     upstream_transport=router, tool_transport=router)
    sc = agent_demo.SCENARIOS[scenario]
    key = {"AICL_KEY_SUPPORT": "k-support", "AICL_KEY_RESEARCH": "k-research"}[sc["key_env"]]
    lines: list[str] = []
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://aicl") as client,
    ):
        res = await agent_demo.run_agent(client, key=key, task=sc["task"], tools=sc["tools"], model=model,
                                         log=lines.append)
    return res, lines


async def test_benign_task_is_answered(tmp_path):
    res, _ = await _agent(tmp_path, [call("search_docs", {"query": "warranty"}),
                                     {"role": "assistant", "content": "The warranty is 24 months."}], "benign")
    assert res["outcome"] == "answered" and "24 months" in res["answer"]
    assert [s.get("tool") for s in res["steps"] if s["kind"] == "tool"] == ["search_docs"]


async def test_email_after_untrusted_docs_is_stopped_by_taint(tmp_path):
    res, lines = await _agent(tmp_path, [
        call("search_docs", {"query": "warranty"}),
        call("send_email", {"to": "boss@example.com", "subject": "Warranty", "body": "24 months."}, "c2"),
    ], "taint")
    assert res["outcome"] == "blocked"
    last = res["steps"][-1]
    assert last["status"] == 403 and last["error"]["control_id"] == "C-TAINT"  # the model's proposal is stopped
    assert any("C-TAINT" in line or "tainted" in line for line in lines)


async def test_hidden_instruction_in_fetched_page_is_blocked(tmp_path):
    res, _ = await _agent(tmp_path, [call("fetch_url", {"url": "https://evil.example/review"}),
                                     {"role": "assistant", "content": "The page could not be read."}],
                          "indirect", model="ollama-local")
    tool_step = next(s for s in res["steps"] if s["kind"] == "tool")
    assert tool_step["status"] == 403 and res["outcome"] == "answered"


@pytest.mark.parametrize("scenario", list(agent_demo.SCENARIOS))
def test_scenarios_use_tools_known_to_the_policy(scenario):
    import yaml

    policy = yaml.safe_load((REPO / "policies" / "default.yaml").read_text(encoding="utf-8"))
    assert set(agent_demo.SCENARIOS[scenario]["tools"]) <= set(policy["tools"])

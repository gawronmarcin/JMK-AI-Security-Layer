"""Mock backendów narzędzi (ARCHITECTURE.md §11.4) — nagrywa każde wywołanie.

Jedna aplikacja, jedno narzędzie = jedna ścieżka:
  POST /tools/search_docs   -> AICL_TOOL_DOCS_URL
  POST /tools/fetch_url     -> AICL_TOOL_FETCH_URL
  POST /tools/send_email    -> AICL_TOOL_MAIL_URL
  POST /tools/run_shell     -> AICL_TOOL_SHELL_URL   (NIGDY niczego nie wykonuje)
  POST /tools/{dowolne}     -> generyczne echo

ZAŁOŻENIE (do potwierdzenia z R1 — protokół gateway→backend nie jest w kontrakcie):
  request : {"tool": str, "arguments": object, "session_id"?: str}
            (akceptujemy też "gołe" argumenty jako body)
  response: {"result": str | object}

Wynik wybierany jest po argumentach (deterministycznie, bez nagłówków):
  search_docs.query zawiera "poison" -> zatruty dokument z ukrytą instrukcją
                    zawiera "pii"    -> dokument z fałszywymi PII
                    zawiera "secret" -> dokument z fałszywym kluczem
                    zawiera "canary" -> dokument z kanarkiem
  fetch_url.url     zawiera "evil"   -> złośliwa strona WWW (indirect injection)
albo nagłówkiem X-Mock-Scenario (jeśli gateway go przekazuje):
  fixed:<text> | poisoned | leak_pii | leak_secret | leak_canary | slow:<ms> | error:<code>
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tests.mocks import fake_data as fd
from tests.mocks.mock_llm import parse_scenario


def _search_docs(args: dict) -> str:
    q = str(args.get("query", "")).casefold()
    if "poison" in q:
        return fd.POISONED_DOC
    if "pii" in q:
        return f"CRM export: {fd.LEAK_PII_TEXT}"
    if "secret" in q:
        return f"config.ini: {fd.LEAK_SECRET_TEXT}"
    if "canary" in q:
        return f"internal note {fd.canaries()[0]}"
    return fd.BENIGN_DOC


def _fetch_url(args: dict) -> str:
    url = str(args.get("url", "")).casefold()
    return fd.MALICIOUS_WEB_PAGE if "evil" in url else fd.BENIGN_WEB_PAGE


def _send_email(args: dict) -> dict:
    return {"status": "sent", "message_id": f"mock-{int(time.time() * 1000)}",
            "to": args.get("to")}


def _run_shell(args: dict) -> dict:
    # Nigdy nie wykonujemy komendy — to tylko atrapa (reguła bezpieczeństwa §0.5/§0.6).
    return {"exit_code": 0, "stdout": "mock-shell: command NOT executed", "stderr": ""}


HANDLERS = {"search_docs": _search_docs, "fetch_url": _fetch_url,
            "send_email": _send_email, "run_shell": _run_shell}


def _scenario_result(name: str, arg: str) -> Any:
    return {"fixed": arg, "poisoned": fd.POISONED_DOC, "leak_pii": fd.LEAK_PII_TEXT,
            "leak_secret": fd.LEAK_SECRET_TEXT,
            "leak_canary": f"note {fd.canaries()[0]}"}.get(name)


def create_app() -> FastAPI:
    app = FastAPI(title="AICL mock tools")
    calls: list[dict[str, Any]] = []
    app.state.calls = calls

    @app.post("/tools/{tool}")
    async def invoke(tool: str, request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            body = {}
        args = body.get("arguments", body) if isinstance(body, dict) else {}
        raw = request.headers.get("x-mock-scenario")
        calls.append({"ts": time.time(), "tool": tool, "arguments": args,
                      "session_id": (body.get("session_id") if isinstance(body, dict) else None)
                      or request.headers.get("x-aicl-session"),
                      "request_id": request.headers.get("x-aicl-request-id"),
                      "scenario": raw})
        if raw:
            sc = parse_scenario(raw)
            if sc["slow_ms"]:
                await asyncio.sleep(sc["slow_ms"] / 1000)
            if sc["error"]:
                return JSONResponse(status_code=sc["error"], content={"error": "scripted"})
            scripted = _scenario_result(sc["content"], sc["content_arg"])
            if scripted is not None:
                return JSONResponse({"result": scripted})
        handler = HANDLERS.get(tool)
        result = handler(args) if handler else {"echo": args}
        return JSONResponse({"result": result})

    @app.get("/__calls")
    async def get_calls(tool: str | None = None) -> dict:
        items = [c for c in calls if tool is None or c["tool"] == tool]
        return {"count": len(items), "calls": items}

    @app.post("/__reset")
    async def reset() -> dict:
        calls.clear()
        return {"ok": True}

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True, "service": "mock-tools"}

    return app


app = create_app()  # dla: uvicorn tests.mocks.mock_tools:app

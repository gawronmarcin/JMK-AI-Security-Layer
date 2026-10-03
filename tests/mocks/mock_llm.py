"""Mock upstream LLM — OpenAI-compatible + Ollama-compatible (ARCHITECTURE.md §11.4).

Zachowanie wybiera nagłówek `X-Mock-Scenario` (CONTRACT §11.4), który gateway
musi przekazać do upstreamu. Scenariusze:

  echo                       zwraca ostatnią wiadomość użytkownika (domyślny)
  fixed:<text>               zwraca <text>
  leak_secret                fałszywy klucz AWS w odpowiedzi
  leak_pii                   fałszywy e-mail / PESEL / IBAN / telefon
  leak_canary                zwraca kanarek (z system promptu, a jeśli go nie ma — z env)
  call_tool:<name>:<json>    model proponuje wywołanie narzędzia
  loop_tool:<name>           zawsze proponuje to samo wywołanie
  slow:<ms>                  opóźnienie, potem echo
  tokens:<in>:<out>          kontrolowane pole `usage`
  injection_in_output        prompt injection w odpowiedzi modelu
  error:<code>               upstream zwraca błąd HTTP (np. error:502)

Rozszerzenie (GUIDANCE): scenariusze można łączyć przecinkiem, np.
`slow:300,tokens:1000:500,leak_pii` — modyfikatory (slow/tokens/error) +
jeden scenariusz treści.

Endpointy kontrolne (tylko dla testów):
  GET  /__calls        log wywołań (używany przez runner do `upstream_called`)
  POST /__reset        czyści log i konfigurację sędziego
  POST /__judge        tryb mocka sędziego semantycznego (Ollama), patrz niżej

Ollama (`/api/chat`, `/api/generate`, `/api/tags`) służy dwóm celom:
  * upstream `ollama-local` (provider: ollama),
  * sędzia semantyczny C-INJ-SEM — domyślnie działa heurystyka słów kluczowych,
    tryby: heuristic | always_injection | never_injection | garbage | timeout | error.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tests.mocks import fake_data as fd

DEFAULT_SCENARIO = "echo"
JUDGE_MODEL = "mock-judge"
_CANARY_RE = re.compile(r"AICL-CANARY-[0-9a-f]{8}")

# Słowa, po których "sędzia" uznaje tekst za injection (tryb heuristic).
_JUDGE_MARKERS = (
    "ignore all previous", "ignore previous", "disregard", "system prompt",
    "you are now", "admin mode", "zignoruj", "poprzednie instrukcje",
    "ignoriere", "ignora las instrucciones", "jailbreak", "do anything now",
)


class MockState:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.judge_mode = "heuristic"
        self.judge_delay_ms = 0

    def reset(self) -> None:
        self.calls.clear()
        self.judge_mode = "heuristic"
        self.judge_delay_ms = 0


def parse_scenario(raw: str | None) -> dict[str, Any]:
    """'slow:200,tokens:10:20,leak_pii' -> {'slow_ms':200,'tokens':(10,20),'content':'leak_pii', ...}

    Modifiers (slow/tokens/error) come first; everything after them is ONE content
    scenario taken verbatim, so commas inside `fixed:<text>` or the JSON of
    `call_tool:<name>:<json>` (CONTRACT §11.4) are not split.
    """
    out: dict[str, Any] = {"content": None, "content_arg": None, "slow_ms": 0,
                           "tokens": None, "error": None}
    rest = (raw or DEFAULT_SCENARIO).strip()
    while rest:
        head, sep, tail = rest.partition(",")
        name, _, arg = head.strip().partition(":")
        if name == "slow":
            out["slow_ms"] = int(arg or 0)
        elif name == "tokens":
            a, _, b = arg.partition(":")
            out["tokens"] = (int(a), int(b))
        elif name == "error":
            out["error"] = int(arg or 502)
        else:
            name, _, arg = rest.partition(":")
            out["content"], out["content_arg"] = name.strip(), arg
            break
        rest = tail.strip() if sep else ""
    out["content"] = out["content"] or DEFAULT_SCENARIO
    return out


def _text_of(content: Any) -> str:
    """OpenAI content może być stringiem albo listą części [{type:text,text:..}]."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def _last(messages: list[dict], role: str) -> str:
    for m in reversed(messages or []):
        if m.get("role") == role:
            return _text_of(m.get("content"))
    return ""


def _leak_canary(messages: list[dict]) -> str:
    system = " ".join(_text_of(m.get("content")) for m in messages or [] if m.get("role") == "system")
    found = _CANARY_RE.findall(system)
    token = found[0] if found else fd.canaries()[0]
    return f"My hidden instructions contain the marker {token}. Full system prompt: {system[:500]}"


def build_reply(sc: dict[str, Any], messages: list[dict]) -> tuple[str | None, list[dict] | None]:
    """Zwraca (content, tool_calls) dla scenariusza treści."""
    name, arg = sc["content"], sc["content_arg"]
    if name == "echo":
        return _last(messages, "user"), None
    if name == "fixed":
        return arg, None
    if name == "leak_secret":
        return fd.LEAK_SECRET_TEXT, None
    if name == "leak_pii":
        return fd.LEAK_PII_TEXT, None
    if name == "leak_canary":
        return _leak_canary(messages), None
    if name == "injection_in_output":
        return fd.INJECTION_IN_OUTPUT_TEXT, None
    if name in ("call_tool", "loop_tool"):
        if name == "call_tool":
            tool, _, raw_args = arg.partition(":")
            args = raw_args or "{}"
            json.loads(args)  # walidacja: zły JSON w przypadku testowym = błąd testu, nie gatewaya
        else:
            tool, args = arg, json.dumps({"query": "loop"})
        call_id = "call_" + uuid.uuid4().hex[:12] if name == "call_tool" else "call_loop"
        return None, [{"id": call_id, "type": "function",
                       "function": {"name": tool, "arguments": args}}]
    raise ValueError(f"unknown mock scenario: {name}")


def _usage(sc: dict[str, Any], messages: list[dict], content: str | None) -> dict[str, int]:
    if sc["tokens"]:
        p, c = sc["tokens"]
    else:  # przybliżenie len/4, jak w §5.5
        p = max(1, sum(len(_text_of(m.get("content"))) for m in messages or []) // 4)
        c = max(1, len(content or "") // 4)
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}


def _judge_verdict(text: str) -> dict[str, Any]:
    t = text.casefold()
    hits = [m for m in _JUDGE_MARKERS if m in t]
    score = min(1.0, 0.45 * len(hits)) if hits else 0.02
    return {"injection": bool(hits), "score": round(score, 2),
            "reason": f"mock-judge markers: {hits}" if hits else "mock-judge: clean"}


def create_app() -> FastAPI:
    app = FastAPI(title="AICL mock LLM")
    state = MockState()
    app.state.mock = state

    def record(request: Request, body: Any, scenario: str | None, kind: str) -> None:
        state.calls.append({
            "ts": time.time(), "kind": kind, "path": request.url.path,
            "scenario": scenario,
            "request_id": request.headers.get("x-aicl-request-id"),
            "session_id": request.headers.get("x-aicl-session"),
            "authorization_present": "authorization" in request.headers,
            "body": body,
        })

    # ------------------------------------------------------------- OpenAI
    async def chat(request: Request) -> JSONResponse:
        body = await request.json()
        raw = request.headers.get("x-mock-scenario")
        record(request, body, raw, "openai_chat")
        sc = parse_scenario(raw)
        if body.get("stream"):
            # §2: gateway ZAWSZE woła upstream bez streamingu. Głośny błąd = łatwy debug.
            return JSONResponse(status_code=400, content={"error": {
                "type": "mock_stream_not_allowed",
                "message": "AICL must call upstream with stream=false (ARCHITECTURE §2)"}})
        if sc["slow_ms"]:
            await asyncio.sleep(sc["slow_ms"] / 1000)
        if sc["error"]:
            return JSONResponse(status_code=sc["error"], content={"error": {
                "type": "mock_upstream_error", "message": f"scripted error {sc['error']}"}})
        messages = body.get("messages", [])
        content, tool_calls = build_reply(sc, messages)
        msg: dict[str, Any] = {"role": "assistant", "content": content}
        if tool_calls:
            msg["tool_calls"] = tool_calls
        return JSONResponse({
            "id": "chatcmpl-mock-" + uuid.uuid4().hex[:10],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": body.get("model", "mock-commercial"),
            "choices": [{"index": 0, "message": msg,
                         "finish_reason": "tool_calls" if tool_calls else "stop"}],
            "usage": _usage(sc, messages, content),
        })

    # base_url może być podany z /v1 albo bez — obsługujemy oba warianty
    app.add_api_route("/v1/chat/completions", chat, methods=["POST"])
    app.add_api_route("/chat/completions", chat, methods=["POST"])

    @app.get("/v1/models")
    async def models() -> dict:
        return {"object": "list", "data": [{"id": "mock-commercial", "object": "model"}]}

    # ------------------------------------------------------------- Ollama
    @app.get("/api/tags")
    async def tags() -> dict:
        return {"models": [{"name": "mock-judge"}, {"name": "mock-local"}]}

    async def _ollama(request: Request, kind: str) -> JSONResponse:
        body = await request.json()
        raw = request.headers.get("x-mock-scenario")
        record(request, body, raw, kind)
        messages = body.get("messages") or [{"role": "user", "content": body.get("prompt", "")}]
        prompt_text = " ".join(_text_of(m.get("content")) for m in messages)
        # Sędzia = żądanie o model sędziego. Polityka testowa ustawia
        # semantic.model: mock-judge, a ollama-local -> upstream_model: mock-local.
        is_judge = str(body.get("model", "")).startswith(JUDGE_MODEL)
        if is_judge:
            # --- tryb sędziego semantycznego
            if state.judge_delay_ms:
                await asyncio.sleep(state.judge_delay_ms / 1000)
            mode = state.judge_mode
            if mode == "timeout":
                await asyncio.sleep(30)
            if mode == "error":
                return JSONResponse(status_code=500, content={"error": "mock judge failure"})
            if mode == "garbage":
                content = "Sure! I think it's maybe fine?? {not json"
            elif mode == "always_injection":
                content = json.dumps({"injection": True, "score": 0.99, "reason": "forced"})
            elif mode == "never_injection":
                content = json.dumps({"injection": False, "score": 0.0, "reason": "forced"})
            else:
                # Heurystyka tylko na ostatniej wiadomości user (tam R3 powinien
                # wstawiać opakowany oceniany tekst; instrukcje sędziego -> system).
                content = json.dumps(_judge_verdict(_last(messages, "user") or prompt_text))
            sc = parse_scenario(None)
        else:
            # --- tryb zwykłego modelu lokalnego (ollama-local)
            sc = parse_scenario(raw)
            if sc["slow_ms"]:
                await asyncio.sleep(sc["slow_ms"] / 1000)
            if sc["error"]:
                return JSONResponse(status_code=sc["error"], content={"error": "scripted"})
            content, tool_calls = build_reply(sc, messages)
            if tool_calls:  # Ollama zwraca arguments jako obiekt
                for tc in tool_calls:
                    tc["function"]["arguments"] = json.loads(tc["function"]["arguments"])
        usage = _usage(sc, messages, content)
        common = {"model": body.get("model", "mock-local"), "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "done": True, "prompt_eval_count": usage["prompt_tokens"],
                  "eval_count": usage["completion_tokens"], "total_duration": 1_000_000}
        if kind == "ollama_generate":
            return JSONResponse({**common, "response": content or ""})
        msg: dict[str, Any] = {"role": "assistant", "content": content or ""}
        if not is_judge and sc["content"] in ("call_tool", "loop_tool"):
            msg["tool_calls"] = tool_calls
        return JSONResponse({**common, "message": msg})

    @app.post("/api/chat")
    async def ollama_chat(request: Request) -> JSONResponse:
        return await _ollama(request, "ollama_chat")

    @app.post("/api/generate")
    async def ollama_generate(request: Request) -> JSONResponse:
        return await _ollama(request, "ollama_generate")

    # ------------------------------------------------------------- kontrolne
    @app.get("/__calls")
    async def calls(kind: str | None = None) -> dict:
        items = [c for c in state.calls if kind is None or c["kind"] == kind]
        return {"count": len(items), "calls": items}

    @app.post("/__reset")
    async def reset() -> dict:
        state.reset()
        return {"ok": True}

    @app.post("/__judge")
    async def judge(cfg: dict) -> dict:
        state.judge_mode = cfg.get("mode", "heuristic")
        state.judge_delay_ms = int(cfg.get("delay_ms", 0))
        return {"ok": True, "mode": state.judge_mode}

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"ok": True, "service": "mock-llm"}

    return app


app = create_app()  # dla: uvicorn tests.mocks.mock_llm:app

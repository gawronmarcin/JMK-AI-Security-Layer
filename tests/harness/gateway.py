"""Uruchamianie PRAWDZIWEGO gatewaya in-process (ASGI) z izolowaną polityką.

Każdy przypadek dostaje:
  * własny katalog tymczasowy (policy.yaml, audit.jsonl),
  * świeżą instancję aplikacji (czysty StateStore: budżety, taint, pętle),
  * wyczyszczone mocki.
Dzięki temu przypadki są niezależne i mogą iść w dowolnej kolejności.

Gateway jest ładowany przez fabrykę wskazaną w AICL_APP_FACTORY
(domyślnie `aicl.app:create_app`, CONTRACT do potwierdzenia z R1 — patrz pytania).
Dopóki R1 nie dostarczy gatewaya, można użyć zaślepki:
  AICL_APP_FACTORY=tests.stub.stub_gateway:create_app
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import inspect
import json
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from asgi_lifespan import LifespanManager

from tests.harness import policy_utils as pu
from tests.mocks import fake_data as fd

DEFAULT_FACTORY = "aicl.app:create_app"
ADMIN_IDENTITY = "admin"


def load_factory():
    spec = os.environ.get("AICL_APP_FACTORY", DEFAULT_FACTORY)
    module_name, _, attr = spec.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, attr or "create_app")


@dataclass
class Mocks:
    llm_url: str
    tools_url: str

    def env(self) -> dict[str, str]:
        t = self.tools_url
        return {
            "AICL_UPSTREAM_MOCK_URL": f"{self.llm_url}/v1",
            "AICL_OLLAMA_URL": self.llm_url,
            "AICL_TOOL_DOCS_URL": f"{t}/tools/search_docs",
            "AICL_TOOL_FETCH_URL": f"{t}/tools/fetch_url",
            "AICL_TOOL_MAIL_URL": f"{t}/tools/send_email",
            "AICL_TOOL_SHELL_URL": f"{t}/tools/run_shell",
        }


@dataclass
class GatewayHandle:
    client: httpx.AsyncClient
    mock_http: httpx.AsyncClient
    mocks: Mocks
    policy: dict[str, Any]
    policy_path: Path
    audit_path: Path
    keys: dict[str, str]
    _audit_offset: int = field(default=0)

    # ---------------------------------------------------------------- mocki
    async def reset_mocks(self) -> None:
        await self.mock_http.post(f"{self.mocks.llm_url}/__reset")
        await self.mock_http.post(f"{self.mocks.tools_url}/__reset")

    async def downstream_calls(self) -> dict[str, list[dict]]:
        llm = (await self.mock_http.get(f"{self.mocks.llm_url}/__calls")).json()["calls"]
        tools = (await self.mock_http.get(f"{self.mocks.tools_url}/__calls")).json()["calls"]
        judge = [c for c in llm if str((c.get("body") or {}).get("model", "")).startswith(pu.JUDGE_MODEL)]
        upstream = [c for c in llm if c not in judge]
        return {"upstream": upstream, "judge": judge, "tools": tools}

    async def set_judge(self, mode: str, delay_ms: int = 0) -> None:
        await self.mock_http.post(f"{self.mocks.llm_url}/__judge",
                                  json={"mode": mode, "delay_ms": delay_ms})

    # ---------------------------------------------------------------- audyt
    def audit_events(self) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        out = []
        for line in self.audit_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"_invalid_line": line[:200]})
        return out

    async def audit_for(self, request_id: str | None, timeout: float = 2.0) -> dict | None:
        """Audyt pisze osobny task (asyncio.Queue, §2) — czekamy chwilę na zdarzenie."""
        if not request_id:
            return None
        deadline = time.monotonic() + timeout
        while True:
            for ev in self.audit_events():
                if ev.get("request_id") == request_id and ev.get("type", "request") == "request":
                    return ev
            if time.monotonic() > deadline:
                return None
            await asyncio.sleep(0.02)

    # ---------------------------------------------------------------- polityka
    def write_policy(self, policy: dict[str, Any]) -> None:
        """Zapis atomowy (tmp + rename), żeby watcher nigdy nie zobaczył pół pliku."""
        tmp = self.policy_path.with_suffix(".tmp")
        pu.dump(policy, tmp)
        os.replace(tmp, self.policy_path)
        self.policy = policy

    def auth(self, identity: str | None = ADMIN_IDENTITY) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.keys[identity]}"} if identity else {}


def build_policy(overlay: dict | None = None, profile: str | None = None,
                 identity: str | None = None, workdir: Path | None = None) -> dict[str, Any]:
    policy = pu.deep_merge(pu.load_base_policy(), overlay or {})
    policy = pu.force_profile(policy, profile, identity)
    if workdir is not None:
        policy = pu.apply_test_environment(policy, workdir)
    return policy


@contextlib.asynccontextmanager
async def running_gateway(mocks: Mocks, workdir: Path, overlay: dict | None = None,
                          profile: str | None = None, identity: str | None = None,
                          extra_env: dict[str, str] | None = None) -> AsyncIterator[GatewayHandle]:
    workdir.mkdir(parents=True, exist_ok=True)
    policy = build_policy(overlay, profile, identity, workdir)
    policy_path = workdir / "policy.yaml"
    pu.dump(policy, policy_path)
    keys, key_env = pu.identity_keys(policy)

    env = {
        "AICL_POLICY": str(policy_path),
        "AICL_ADMIN_OPEN": "0",
        "AICL_CANARY_1": fd.DEFAULT_CANARIES[0],
        "AICL_CANARY_2": fd.DEFAULT_CANARIES[1],
        **mocks.env(), **key_env, **(extra_env or {}),
    }
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        factory = load_factory()
        app = factory()
        if inspect.isawaitable(app):
            app = await app
        async with LifespanManager(app, startup_timeout=30, shutdown_timeout=10) as manager:
            transport = httpx.ASGITransport(app=manager.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://aicl.test",
                                         timeout=30) as client, \
                       httpx.AsyncClient(timeout=10) as mock_http:
                handle = GatewayHandle(client=client, mock_http=mock_http, mocks=mocks,
                                       policy=policy, policy_path=policy_path,
                                       audit_path=Path(policy["audit"]["path"]), keys=keys)
                await handle.reset_mocks()
                yield handle
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

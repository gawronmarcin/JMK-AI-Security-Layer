"""§9: sędziowie będą edytować politykę NA ŻYWO. Zmiana pliku na dysku -> inne
zachowanie przy następnym żądaniu (≤ ~1 s), bez restartu. Zły plik -> stara polityka.

Obserwujemy to przez C-PII-OUT na skryptowanym wycieku PII (balanced: redact,
permissive: flag), żeby testy reloadu nie zależały od konkretnego detektora."""

from __future__ import annotations

import asyncio
import copy
import time

import pytest

pytestmark = pytest.mark.gateway

REQUEST = {"model": "mock-commercial", "messages": [{"role": "user", "content": "Who is the customer?"}]}
LEAK = {"X-Mock-Scenario": "leak_pii"}
RELOAD_TIMEOUT_S = 3.0      # cel to ~1 s; zapas na wolne CI


async def _wait_for(predicate, timeout=RELOAD_TIMEOUT_S):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if await predicate():
            return time.monotonic() - t0
        await asyncio.sleep(0.1)
    return None


async def _action(gw, headers) -> str | None:
    r = await gw.client.post("/v1/chat/completions", json=REQUEST, headers=headers)
    return r.headers.get("x-aicl-action") if r.status_code == 200 else None


async def test_disable_control_takes_effect_without_restart(gateway):
    async with gateway(profile="balanced") as gw:
        h = {**gw.auth("support-agent-01"), **LEAK}
        assert await _action(gw, h) == "redact"
        v1 = (await gw.client.get("/healthz")).json().get("policy_version")

        p = copy.deepcopy(gw.policy)
        p["controls"]["pii_output"]["enabled"] = False
        gw.write_policy(p)

        async def allowed():
            return await _action(gw, h) == "allow"
        took = await _wait_for(allowed)
        assert took is not None, "zmiana polityki nie zadziałała w czasie"
        v2 = (await gw.client.get("/healthz")).json().get("policy_version")
        assert v1 != v2, "policy_version musi się zmienić po reloadzie"
        print(f"hot reload took {took:.2f}s")


async def test_switch_active_profile_live(gateway):
    async with gateway() as gw:
        h = {**gw.auth("support-agent-01"), **LEAK}
        p = copy.deepcopy(gw.policy)
        for i in p["identities"]:
            i.pop("profile", None)
        p["active_profile"] = "permissive"
        gw.write_policy(p)

        async def flagged():
            return await _action(gw, h) == "flag"
        assert await _wait_for(flagged) is not None


async def test_invalid_policy_keeps_old_one(gateway):
    async with gateway(profile="balanced") as gw:
        h = {**gw.auth("support-agent-01"), **LEAK}
        v1 = (await gw.client.get("/healthz")).json().get("policy_version")
        gw.policy_path.write_text("version: 1\ncontrols: {pii_output: {enabeld: maybe}}\nnot_a_key: 1\n")
        await asyncio.sleep(RELOAD_TIMEOUT_S / 2)
        assert await _action(gw, h) == "redact", "po złym pliku musi działać stara polityka"
        assert (await gw.client.get("/healthz")).json().get("policy_version") == v1
        types = [e.get("type") for e in gw.audit_events()]
        assert "policy.rejected" in types, f"brak zdarzenia policy.rejected w audycie: {types}"

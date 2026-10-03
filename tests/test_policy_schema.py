"""Walidacja polityki przez /admin/policy/validate (GUIDANCE §5.1): literówki muszą być
odrzucane (extra=forbid), poprawna polityka akceptowana, endpoint tylko dla admina."""

from __future__ import annotations

import pytest
import yaml

from tests.harness.policy_utils import load_base_policy

pytestmark = pytest.mark.gateway

BAD = {
    "unknown_top_level_key": lambda p: p.update({"contorls": {}}),
    "wrong_version": lambda p: p.update({"version": 99}),
    "not_a_mapping": None,
}


async def test_valid_policy_accepted(gateway):
    async with gateway() as gw:
        r = await gw.client.post("/admin/policy/validate", content=yaml.safe_dump(load_base_policy()),
                                 headers=gw.auth("admin"))
        assert r.status_code == 200, r.text


@pytest.mark.parametrize("name", list(BAD))
async def test_invalid_policy_rejected(gateway, name):
    async with gateway() as gw:
        if BAD[name] is None:
            body = "- just\n- a list\n"
        else:
            p = load_base_policy()
            BAD[name](p)
            body = yaml.safe_dump(p)
        r = await gw.client.post("/admin/policy/validate", content=body, headers=gw.auth("admin"))
        assert r.status_code in (400, 422), f"{name}: oczekiwany błąd walidacji, jest {r.status_code}"


async def test_validate_requires_admin(gateway):
    async with gateway() as gw:
        r = await gw.client.post("/admin/policy/validate", content="version: 1",
                                 headers=gw.auth("support-agent-01"))
        assert r.status_code in (401, 403)

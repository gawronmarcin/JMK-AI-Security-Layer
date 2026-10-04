"""Group C tests: Hybrid policy validation and dev-key warning audit event."""

from __future__ import annotations

import pytest

from aicl.app import create_app
from aicl.audit import iter_events
from aicl.policy.loader import load_policy_file


def test_hybrid_policy_loads():
    policy = load_policy_file("policies/hybrid.yaml", {})
    assert policy.raw.version == 1
    assert policy.raw.meta.name == "hybrid-policy"

    # Embedding backend is ollama, model bge-m3
    emb_spec = policy.raw.controls.get("injection_embedding")
    assert emb_spec is not None
    assert emb_spec.params.get("backend") == "ollama"
    assert emb_spec.params.get("model") == "bge-m3"

    # Bastion backend is protectai
    bastion_spec = policy.raw.controls.get("injection_bastion")
    assert bastion_spec is not None
    assert bastion_spec.params.get("backend") == "protectai"


@pytest.mark.asyncio
async def test_dev_key_warning_audit(tmp_path):
    audit_file = tmp_path / "audit_dev_warning.jsonl"
    env = {
        "AICL_KEY_SUPPORT": "dev-key-support",
        "AICL_KEY_RESEARCH": "dev-key-research",
        "AICL_KEY_ADMIN": "dev-key-admin",
    }

    app = create_app(
        policy_path="policies/hybrid.yaml",
        env=env,
        audit_path=audit_file,
    )

    async with app.router.lifespan_context(app):
        pass

    events = list(iter_events(audit_file))
    # Should have emitted config.warning for dev-key-* identities
    warnings = [e for e in events if e.type == "config.warning"]
    assert len(warnings) > 0
    warning_ev = warnings[0]
    assert "identities using dev-key-*" in warning_ev.detail.get("warning", "")
    assert "support-agent-01" in warning_ev.detail.get("identities", [])

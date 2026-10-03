"""Tests for C-MEM-ACL (memory_acl.py). R3, P1.

Coverage per ARCHITECTURE.md §11.5:
  - ≥3 negative cases (must be blocked)
  - ≥3 positive cases (must be allowed)
  - ≥2 edge cases (unknown namespace, wildcard role, no-namespace tool, retrieved segments)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aicl.controls.memory_acl import MemoryAcl
from aicl.models import Action, Origin, RequestContext, Segment, Stage
from aicl.normalize import build_segment
from aicl.policy.loader import load_policy_file

REPO = Path(__file__).parents[1]
POLICY_PATH = REPO / "policies" / "default.yaml"

ENV = {
    "AICL_KEY_SUPPORT": "key-support",
    "AICL_KEY_RESEARCH": "key-research",
    "AICL_KEY_ADMIN": "key-admin",
    "AICL_UPSTREAM_MOCK_URL": "http://mock",
    "AICL_OLLAMA_URL": "http://ollama",
}


@pytest.fixture
def policy():
    return load_policy_file(POLICY_PATH, ENV)


def tool_ctx(
    tool: str,
    args: dict,
    *,
    role: str = "support_agent",
    identity: str = "support-agent-01",
    profile: str = "balanced",
    session_id: str = "s-mem",
) -> RequestContext:
    return RequestContext(
        request_id="req-mem",
        session_id=session_id,
        endpoint="chat",
        stage=Stage.tool_call,
        identity=identity,
        role=role,
        profile=profile,  # type: ignore[arg-type]
        model="mock-commercial",
        segments=[],
        tool=tool,
        tool_args=args,
        risk=0.0,
        tainted=False,
        policy_version="test",
    )


def input_ctx(
    segments: list[Segment],
    *,
    role: str = "support_agent",
    identity: str = "support-agent-01",
    profile: str = "balanced",
    session_id: str = "s-mem",
) -> RequestContext:
    return RequestContext(
        request_id="req-mem",
        session_id=session_id,
        endpoint="chat",
        stage=Stage.input,
        identity=identity,
        role=role,
        profile=profile,  # type: ignore[arg-type]
        model="mock-commercial",
        segments=segments,
        risk=0.0,
        tainted=False,
        policy_version="test",
    )


def retrieved_seg(idx: int, namespace: str, text: str = "content") -> Segment:
    return build_segment(idx, text, Origin.retrieved, "untrusted", {"namespace": namespace})


# =============================================================================
# NEGATIVE — must be blocked
# =============================================================================

async def test_support_agent_blocked_from_kb_hr_tool_call(policy):
    """support_agent only has kb_public; kb_hr is restricted."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx("memory_read", {"namespace": "kb_hr", "query": "salary data"})

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.block
    assert d.threat_ids == ["TH-10"]
    assert "kb_hr" in d.reason
    assert any(m.kind == "unauthorized_namespace" for m in d.matches)


async def test_support_agent_blocked_from_kb_research_tool_call(policy):
    """kb_research is internal; support_agent does not have access."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx("rag_query", {"namespace": "kb_research", "query": "internal docs"})

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.block
    assert "kb_research" in d.reason


async def test_researcher_blocked_from_kb_hr(policy):
    """researcher has kb_public + kb_research, NOT kb_hr."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx(
        "kb_search",
        {"namespace": "kb_hr"},
        role="researcher",
        identity="research-agent-01",
    )

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.block
    assert "kb_hr" in d.reason


async def test_retrieved_segment_from_restricted_namespace_is_blocked(policy):
    """A RAG segment arriving via Origin.retrieved from kb_hr must be blocked."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    segs = [retrieved_seg(0, "kb_hr", "employee compensation details")]
    ctx = input_ctx(segs)

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.block
    assert "kb_hr" in d.reason
    assert any(m.segment_idx == 0 for m in d.matches)


# =============================================================================
# POSITIVE — must be allowed
# =============================================================================

async def test_support_agent_allowed_kb_public(policy):
    """support_agent is explicitly granted kb_public."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx("memory_read", {"namespace": "kb_public", "query": "help article"})

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.allow


async def test_researcher_allowed_kb_research(policy):
    """researcher is explicitly granted kb_research."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx(
        "rag_query",
        {"namespace": "kb_research"},
        role="researcher",
        identity="research-agent-01",
    )

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.allow


async def test_admin_wildcard_allows_any_namespace(policy):
    """admin role has memory_namespaces: ['*']."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx("memory_read", {"namespace": "kb_hr"}, role="admin", identity="admin")

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.allow


async def test_non_memory_tool_without_namespace_arg_is_skipped(policy):
    """Regular tool with no namespace arg: C-MEM-ACL should stay out of the way."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx("search_docs", {"query": "how to refund"})

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.allow
    assert "does not involve" in d.reason


async def test_retrieved_segment_from_allowed_namespace_passes(policy):
    """Researcher gets a RAG segment from kb_research: allowed."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    segs = [retrieved_seg(0, "kb_research", "research doc")]
    ctx = input_ctx(segs, role="researcher", identity="research-agent-01")

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.allow


# =============================================================================
# EDGE CASES
# =============================================================================

async def test_unknown_namespace_is_blocked(policy):
    """A namespace not declared in the policy at all must be blocked."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx("memory_read", {"namespace": "kb_totally_unknown"})

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.block
    assert "Unknown namespace" in d.reason


async def test_memory_namespace_key_alias_detected(policy):
    """Arg key 'memory_namespace' (alias) should be detected the same as 'namespace'."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    ctx = tool_ctx("memory_read", {"memory_namespace": "kb_hr", "query": "private"})

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.block


async def test_permissive_profile_flags_instead_of_blocks(policy):
    """In permissive mode the configured action is 'flag', not 'block'."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "permissive")
    ctx = tool_ctx("memory_read", {"namespace": "kb_hr"}, profile="permissive")

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.flag


async def test_retrieved_segment_without_namespace_meta_is_allowed(policy):
    """A retrieved segment with no 'namespace' key in meta should pass silently."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    seg = build_segment(0, "some retrieved text", Origin.retrieved, "untrusted", {})
    ctx = input_ctx([seg])

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.allow


async def test_mixed_retrieved_segments_one_bad_one_good_is_blocked(policy):
    """If even one retrieved segment is from a restricted namespace, block."""
    ctrl = MemoryAcl()
    cfg = policy.level_config("C-MEM-ACL", "balanced")
    segs = [
        retrieved_seg(0, "kb_public", "safe content"),
        retrieved_seg(1, "kb_hr", "restricted content"),
    ]
    ctx = input_ctx(segs)

    d = await ctrl.evaluate(ctx, cfg)

    assert d.action == Action.block
    # Only the bad segment is in matches
    assert len(d.matches) == 1
    assert d.matches[0].segment_idx == 1

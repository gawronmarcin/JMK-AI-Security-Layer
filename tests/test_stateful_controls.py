"""Unit tests for R3 stateful controls:
- C-TOOL-ACL (tool_acl.py)
- C-BUDGET (budget.py)
- C-LOOP (loop.py)
- C-TAINT (taint.py)
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aicl.controls.budget import BudgetGuard
from aicl.controls.loop import LoopGuard
from aicl.controls.taint import TaintGuard
from aicl.controls.tool_acl import ToolAcl
from aicl.models import Action, RequestContext, Stage
from aicl.policy.loader import load_policy_file
from aicl.state.memory import InMemoryStore

REPO = Path(__file__).parents[1]
POLICY_PATH = REPO / "policies" / "default.yaml"


@pytest.fixture
def policy():
    env = {
        "AICL_KEY_SUPPORT": "key-support",
        "AICL_KEY_RESEARCH": "key-research",
        "AICL_KEY_ADMIN": "key-admin",
        "AICL_UPSTREAM_MOCK_URL": "http://mock",
        "AICL_OLLAMA_URL": "http://ollama",
    }
    return load_policy_file(POLICY_PATH, env)


def make_ctx(
    *,
    tool: str | None = None,
    tool_args: dict | None = None,
    role: str = "support_agent",
    identity: str = "support-agent-01",
    profile: str = "balanced",
    session_id: str = "s1",
    tainted: bool = False,
    stage: Stage = Stage.tool_call,
) -> RequestContext:
    return RequestContext(
        request_id="req-1",
        session_id=session_id,
        endpoint="chat",
        stage=stage,
        identity=identity,
        role=role,
        profile=profile,  # type: ignore[arg-type]
        model="mock-commercial",
        segments=[],
        tool=tool,
        tool_args=tool_args,
        risk=0.0,
        tainted=tainted,
        policy_version="test-v1",
    )


# ============================================================================
# C-TOOL-ACL Tests
# ============================================================================


async def test_tool_acl_allows_authorized_tool(policy):
    ctrl = ToolAcl()
    cfg = policy.level_config("C-TOOL-ACL", "balanced")
    ctx = make_ctx(tool="search_docs", tool_args={"query": "python tutorial"})

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.allow
    assert decision.threat_ids == ["TH-07"]


async def test_tool_acl_blocks_unauthorized_tool(policy):
    ctrl = ToolAcl()
    cfg = policy.level_config("C-TOOL-ACL", "balanced")
    # support_agent is not allowed to run 'fetch_url' or 'run_shell'
    ctx = make_ctx(tool="run_shell", tool_args={"cmd": "ls"})

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.block
    assert decision.severity == "high"
    assert "not permitted for role" in decision.reason


async def test_tool_acl_blocks_invalid_args_schema(policy):
    ctrl = ToolAcl()
    cfg = policy.level_config("C-TOOL-ACL", "balanced")
    # search_docs requires "query" (string, max 500 chars)
    ctx = make_ctx(tool="search_docs", tool_args={"invalid_key": "val"})

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.block
    assert "failed schema validation" in decision.reason


async def test_tool_acl_permissive_flags_schema_error(policy):
    ctrl = ToolAcl()
    cfg = policy.level_config("C-TOOL-ACL", "permissive")
    # In permissive profile, validate_args is false
    ctx = make_ctx(tool="search_docs", tool_args={"bad": 123}, profile="permissive")

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.allow  # validate_args is false in permissive


async def test_tool_acl_admin_wildcard_allows_all(policy):
    ctrl = ToolAcl()
    cfg = policy.level_config("C-TOOL-ACL", "balanced")
    ctx = make_ctx(tool="run_shell", tool_args={}, role="admin")

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.allow


# ============================================================================
# C-BUDGET Tests
# ============================================================================


async def test_budget_guard_within_limits(policy):
    store = InMemoryStore()
    ctrl = BudgetGuard(store=store)
    cfg = policy.level_config("C-BUDGET", "balanced")
    ctx = make_ctx(stage=Stage.ingress)

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.allow


async def test_budget_guard_blocks_token_overuse(policy):
    store = InMemoryStore()
    # support_default has max_tokens: 200,000
    await store.add_usage("support-agent-01", "day", prompt_tokens=250_000)

    ctrl = BudgetGuard(store=store)
    cfg = policy.level_config("C-BUDGET", "balanced")
    ctx = make_ctx(stage=Stage.ingress)

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.block
    assert "TH-11" in decision.threat_ids
    assert "Token budget exceeded" in decision.reason


async def test_budget_guard_blocks_cost_overuse(policy):
    store = InMemoryStore()
    # support_default has max_cost_usd: 2.00
    await store.add_usage("support-agent-01", "day", cost_usd=2.50)

    ctrl = BudgetGuard(store=store)
    cfg = policy.level_config("C-BUDGET", "balanced")
    ctx = make_ctx(stage=Stage.ingress)

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.block
    assert "TH-12" in decision.threat_ids
    assert "Cost budget exceeded" in decision.reason


async def test_budget_guard_blocks_rpm_limit(policy):
    store = InMemoryStore()
    # support_default has max_requests_per_minute: 30
    await store.add_usage("support-agent-01", "minute", requests=30)

    ctrl = BudgetGuard(store=store)
    cfg = policy.level_config("C-BUDGET", "balanced")
    ctx = make_ctx(stage=Stage.ingress)

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.block
    assert "TH-12" in decision.threat_ids
    assert "Rate limit exceeded" in decision.reason


async def test_budget_guard_admin_unlimited(policy):
    store = InMemoryStore()
    await store.add_usage("admin", "day", prompt_tokens=10_000_000, cost_usd=100.0)

    ctrl = BudgetGuard(store=store)
    cfg = policy.level_config("C-BUDGET", "balanced")
    ctx = make_ctx(role="admin", identity="admin", stage=Stage.ingress)

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.allow


# ============================================================================
# C-LOOP Tests
# ============================================================================


class ControlledClock:
    def __init__(self, start: float = 1_000_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t


async def test_loop_guard_blocks_identical_calls_in_window(policy):
    clock = ControlledClock()
    store = InMemoryStore(clock=clock)
    ctrl = LoopGuard(store=store, clock=clock)
    cfg = policy.level_config("C-LOOP", "balanced")
    # support_default: max_identical_tool_calls: 3, loop_window_seconds: 60
    ctx = make_ctx(tool="search_docs", tool_args={"query": "stuck query"})

    # First 3 identical calls within window should pass
    for _ in range(3):
        d = await ctrl.evaluate(ctx, cfg)
        assert d.action == Action.allow

    # 4th identical call must be blocked
    d4 = await ctrl.evaluate(ctx, cfg)
    assert d4.action == Action.block
    assert "TH-13" in d4.threat_ids
    assert "Runaway loop detected" in d4.reason


async def test_loop_guard_allows_when_window_elapses(policy):
    clock = ControlledClock()
    store = InMemoryStore(clock=clock)
    ctrl = LoopGuard(store=store, clock=clock)
    cfg = policy.level_config("C-LOOP", "balanced")
    ctx = make_ctx(tool="search_docs", tool_args={"query": "repeated"})

    for _ in range(3):
        await ctrl.evaluate(ctx, cfg)

    # Fast forward clock past loop_window_seconds (60s)
    clock.t += 65.0

    # New call after window elapses is permitted
    d = await ctrl.evaluate(ctx, cfg)
    assert d.action == Action.allow


async def test_loop_guard_blocks_total_session_cap(policy):
    store = InMemoryStore()
    ctrl = LoopGuard(store=store)
    cfg = policy.level_config("C-LOOP", "balanced")
    # support_default: max_tool_calls_per_session: 25

    for i in range(25):
        # Vary arguments so identical call limit is not hit
        ctx = make_ctx(tool="search_docs", tool_args={"query": f"distinct-{i}"})
        d = await ctrl.evaluate(ctx, cfg)
        assert d.action == Action.allow

    # 26th call exceeds session limit
    ctx_overflow = make_ctx(tool="search_docs", tool_args={"query": "overflow"})
    d_over = await ctrl.evaluate(ctx_overflow, cfg)
    assert d_over.action == Action.block
    assert "Session tool call cap exceeded" in d_over.reason


# ============================================================================
# C-TAINT Tests
# ============================================================================


async def test_taint_guard_allows_untainted_session(policy):
    store = InMemoryStore()
    ctrl = TaintGuard(store=store)
    cfg = policy.level_config("C-TAINT", "balanced")
    ctx = make_ctx(tool="send_email", tool_args={"to": "a@b.com"}, tainted=False)

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.allow


async def test_taint_guard_allows_low_privilege_in_tainted_session(policy):
    store = InMemoryStore()
    ctrl = TaintGuard(store=store)
    cfg = policy.level_config("C-TAINT", "balanced")
    # search_docs has privilege "low" (not blocked)
    ctx = make_ctx(tool="search_docs", tool_args={"query": "docs"}, tainted=True)

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.allow


async def test_taint_guard_blocks_high_privilege_when_tainted(policy):
    store = InMemoryStore()
    ctrl = TaintGuard(store=store)
    cfg = policy.level_config("C-TAINT", "balanced")
    # send_email has privilege "high" (blocked when tainted)
    ctx = make_ctx(
        tool="send_email",
        tool_args={"to": "ceo@example.com", "subject": "hi", "body": "leak"},
        tainted=True,
    )

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.block
    assert decision.threat_ids == ["TH-19"]
    assert "session 's1' is tainted" in decision.reason
    assert "high" in decision.reason


async def test_taint_guard_detects_session_tainted_in_store(policy):
    store = InMemoryStore()
    # Mark session tainted in store
    await store.mark_tainted("s-tainted", "retrieved_doc")

    ctrl = TaintGuard(store=store)
    cfg = policy.level_config("C-TAINT", "balanced")
    # ctx.tainted is False, but session in store is tainted
    ctx = make_ctx(
        session_id="s-tainted",
        tool="send_email",
        tool_args={"to": "x@y.com"},
        tainted=False,
    )

    decision = await ctrl.evaluate(ctx, cfg)
    assert decision.action == Action.block
    assert decision.threat_ids == ["TH-19"]

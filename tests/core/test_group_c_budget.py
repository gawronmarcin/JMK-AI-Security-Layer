"""Group C tests: Budget limits, concurrency, reserve/settle, and Retry-After headers."""

from __future__ import annotations

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient

from aicl.app import create_app
from aicl.state.base import BudgetLimits
from aicl.state.memory import InMemoryStore
from aicl.state.redis_store import RedisStore
from tests.core.fake_redis import FakeAsyncRedis
from tests.mocks.mock_llm import app as mock_llm_app


@pytest.mark.asyncio
async def test_memory_store_check_and_reserve_and_settle():
    store = InMemoryStore()
    limits = BudgetLimits(max_requests_per_minute=2, max_tokens=1000)

    # First reserve
    res1 = await store.check_and_reserve(
        identity="user1", window="minute", request_id="req_1", tokens=100, cost_usd=0.0, limits=limits
    )
    assert res1.allowed is True

    # Second reserve
    res2 = await store.check_and_reserve(
        identity="user1", window="minute", request_id="req_2", tokens=100, cost_usd=0.0, limits=limits
    )
    assert res2.allowed is True

    # Third reserve exceeds RPM (2 allowed)
    res3 = await store.check_and_reserve(
        identity="user1", window="minute", request_id="req_3", tokens=100, cost_usd=0.0, limits=limits
    )
    assert res3.allowed is False
    assert res3.retry_after_s is not None
    assert res3.retry_after_s > 0

    # Settle first request with actual usage
    await store.settle(request_id="req_1", prompt_tokens=50, completion_tokens=20)

    # Check that usage was settled
    counters = await store.get_usage("user1", "minute")
    assert counters.prompt_tokens == 50
    assert counters.completion_tokens == 20


@pytest.mark.asyncio
async def test_redis_store_check_and_reserve_and_settle():
    client = FakeAsyncRedis()
    store = RedisStore(client)
    limits = BudgetLimits(max_requests_per_minute=2, max_tokens=1000)

    res1 = await store.check_and_reserve(
        identity="user_redis", window="minute", request_id="req_r1", tokens=200, cost_usd=0.0, limits=limits
    )
    assert res1.allowed is True

    res2 = await store.check_and_reserve(
        identity="user_redis", window="minute", request_id="req_r2", tokens=200, cost_usd=0.0, limits=limits
    )
    assert res2.allowed is True

    res3 = await store.check_and_reserve(
        identity="user_redis", window="minute", request_id="req_r3", tokens=200, cost_usd=0.0, limits=limits
    )
    assert res3.allowed is False
    assert res3.retry_after_s is not None

    await store.settle(request_id="req_r1", prompt_tokens=80, completion_tokens=40)
    counters = await store.get_usage("user_redis", "minute")
    assert counters.prompt_tokens == 80
    assert counters.completion_tokens == 40


@pytest.mark.asyncio
async def test_concurrent_requests_rate_limiting(tmp_path):
    policy_text = """
version: 1
active_profile: balanced
mode: enforce
identities:
  - id: bgt-user
    api_key_env: KEY_BGT
    role: agent
    profile: balanced
roles:
  agent:
    models: [mock-llm]
    budget: limited
budgets:
  limited:
    window: minute
    max_requests_per_minute: 5
    max_tokens: 50000
    on_exceed: block
models:
  - name: mock-llm
    provider: openai_compatible
    base_url_env: MOCK_URL
controls:
  budget_guard:
    id: C-BUDGET
    enabled: true
    stages: [ingress]
    levels:
      strict: {action: block}
      balanced: {action: block}
      permissive: {action: flag}
"""
    p_file = tmp_path / "policy.yaml"
    p_file.write_text(policy_text, encoding="utf-8")
    env = {
        "KEY_BGT": "test-key-bgt",
        "MOCK_URL": "http://mock/v1",
    }
    app = create_app(
        policy_path=p_file,
        env=env,
        audit_path=tmp_path / "audit.jsonl",
        upstream_transport=ASGITransport(mock_llm_app),
    )

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = {"Authorization": "Bearer test-key-bgt"}
            body = {
                "model": "mock-llm",
                "messages": [{"role": "user", "content": "hello"}],
            }

            # Launch 15 concurrent requests
            tasks = [client.post("/v1/chat/completions", json=body, headers=headers) for _ in range(15)]
            responses = await asyncio.gather(*tasks)

            statuses = [r.status_code for r in responses]
            successes = [s for s in statuses if s == 200]
            throttled = [s for s in statuses if s == 429]

            assert len(successes) == 5
            assert len(throttled) == 10

            # Check that 429 response contains Retry-After header
            sample_429 = next(r for r in responses if r.status_code == 429)
            assert "retry-after" in sample_429.headers
            retry_val = int(sample_429.headers["retry-after"])
            assert retry_val > 0


# --- Redis budget lock: owner token, frozen clock, contention ----------------------------------

async def test_redis_lock_release_does_not_delete_someone_elses_lock():
    from fake_redis import Data, FakeAsyncRedis

    from aicl.state.redis_store import RedisStore

    store = RedisStore(FakeAsyncRedis(Data()))
    token = await store._acquire_lock("alice")
    assert token is not None
    lock_key = store._k("lock", "budget", "alice")
    await store.r.set(lock_key, "someone-else")  # ours expired and another instance took it
    await store._release_lock("alice", token)
    assert await store.r.get(lock_key) == "someone-else"


async def test_redis_lock_times_out_even_with_a_frozen_clock():
    from fake_redis import Data, FakeAsyncRedis

    from aicl.state.base import BudgetLimits
    from aicl.state.redis_store import RedisStore

    store = RedisStore(FakeAsyncRedis(Data()), clock=lambda: 1000.0)
    await store.r.set(store._k("lock", "budget", "bob"), "held", nx=True, ex=10)
    store_timeout = store._acquire_lock

    async def quick(identity, timeout=5.0):
        return await store_timeout(identity, timeout=0.05)

    store._acquire_lock = quick
    res = await store.check_and_reserve("bob", "day", "req-1", tokens=1, cost_usd=0.0,
                                        limits=BudgetLimits(max_requests_per_minute=10))
    assert not res.allowed and res.exceeded_limit == "busy" and res.retry_after_s == 1.0

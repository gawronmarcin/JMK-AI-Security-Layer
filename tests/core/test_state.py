"""StateStore behaviour, run against both InMemoryStore and RedisStore (fake Redis)."""

import pytest
from fake_redis import Data, FakeAsyncRedis

from aicl.state import InMemoryStore, window_bucket
from aicl.state.redis_store import RedisStore


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture(params=["memory", "redis"])
def make_store(request):
    def make(clock=None, session_ttl_seconds=3600):
        clock = clock or Clock()
        if request.param == "memory":
            return InMemoryStore(session_ttl_seconds=session_ttl_seconds, clock=clock)
        return RedisStore(FakeAsyncRedis(Data(clock)), session_ttl_seconds=session_ttl_seconds, clock=clock)

    return make


async def test_session_taint_and_copy_semantics(make_store):
    store = make_store()
    await store.mark_tainted("s1", "tool:search_docs")
    await store.mark_tainted("s1", "tool:search_docs")
    s = await store.get_session("s1")
    assert s.tainted and s.taint_sources == ["tool:search_docs"]
    s.taint_sources.append("hacked")
    assert (await store.get_session("s1")).taint_sources == ["tool:search_docs"]
    assert not (await store.get_session("s2")).tainted


async def test_tool_calls_recorded_in_order(make_store):
    store = make_store()
    await store.record_tool_call("s1", "search_docs", "h1")
    calls = await store.record_tool_call("s1", "search_docs", "h1")
    assert [(c.tool, c.args_hash) for c in calls] == [("search_docs", "h1")] * 2


async def test_session_expires_after_ttl(make_store):
    clock = Clock()
    store = make_store(clock, session_ttl_seconds=60)
    await store.mark_tainted("s1", "x")
    clock.t += 61
    assert not (await store.get_session("s1")).tainted


async def test_usage_accumulates_per_identity_and_window(make_store):
    clock = Clock()
    store = make_store(clock)
    await store.add_usage("a", "day", requests=1, prompt_tokens=10, completion_tokens=5, cost_usd=0.01)
    u = await store.add_usage("a", "day", requests=1, prompt_tokens=10)
    assert u.requests == 2 and u.tokens == 25 and abs(u.cost_usd - 0.01) < 1e-9
    assert (await store.get_usage("b", "day")).requests == 0


async def test_usage_resets_in_next_window(make_store):
    clock = Clock(t=60 * 1000)  # start of a minute
    store = make_store(clock)
    await store.add_usage("a", "minute", requests=5)
    clock.t += 59
    assert (await store.get_usage("a", "minute")).requests == 5
    clock.t += 1
    assert (await store.get_usage("a", "minute")).requests == 0
    assert all(v.requests == 0 for v in (await store.all_usage()).values())


def test_window_bucket():
    key, expires = window_bucket("hour", now=3600 * 5 + 10)
    assert key == "hour:5" and expires == 3600 * 6


async def test_tool_call_history_is_capped(make_store):
    from aicl.state.memory import MAX_TOOL_CALLS_KEPT

    store = make_store()
    for i in range(MAX_TOOL_CALLS_KEPT + 5):
        calls = await store.record_tool_call("s1", "t", f"h{i}")
    assert len(calls) == MAX_TOOL_CALLS_KEPT and calls[-1].args_hash == f"h{MAX_TOOL_CALLS_KEPT + 4}"


async def test_delegation_depth_and_reset(make_store):
    store = make_store()
    await store.set_delegation_depth("s1", 2)
    await store.add_usage("a", "day", requests=1)
    assert (await store.get_session("s1")).delegation_depth == 2
    await store.reset()
    assert (await store.get_session("s1")).delegation_depth == 0
    assert (await store.get_usage("a", "day")).requests == 0


async def test_redis_counters_are_shared_between_instances():
    """Two gateway instances, one Redis: budgets add up across them."""
    data, clock = Data(Clock()), Clock()
    a = RedisStore(FakeAsyncRedis(data), clock=clock)
    b = RedisStore(FakeAsyncRedis(data), clock=clock)
    await a.add_usage("agent", "day", requests=1, prompt_tokens=10)
    u = await b.add_usage("agent", "day", requests=1, prompt_tokens=5)
    assert u.requests == 2 and u.prompt_tokens == 15
    await a.mark_tainted("s1", "tool")
    assert (await b.get_session("s1")).tainted
    assert set(await b.all_usage()) == {("agent", next(iter(await a.all_usage()))[1])}

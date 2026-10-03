from aicl.state import InMemoryStore, window_bucket


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


async def test_session_taint_and_copy_semantics():
    store = InMemoryStore()
    await store.mark_tainted("s1", "tool:search_docs")
    await store.mark_tainted("s1", "tool:search_docs")
    s = await store.get_session("s1")
    assert s.tainted and s.taint_sources == ["tool:search_docs"]
    s.taint_sources.append("hacked")
    assert (await store.get_session("s1")).taint_sources == ["tool:search_docs"]
    assert not (await store.get_session("s2")).tainted


async def test_tool_calls_recorded_in_order():
    store = InMemoryStore()
    await store.record_tool_call("s1", "search_docs", "h1")
    calls = await store.record_tool_call("s1", "search_docs", "h1")
    assert [(c.tool, c.args_hash) for c in calls] == [("search_docs", "h1")] * 2


async def test_session_expires_after_ttl():
    clock = Clock()
    store = InMemoryStore(session_ttl_seconds=60, clock=clock)
    await store.mark_tainted("s1", "x")
    clock.t += 61
    assert not (await store.get_session("s1")).tainted


async def test_usage_accumulates_per_identity_and_window():
    clock = Clock()
    store = InMemoryStore(clock=clock)
    await store.add_usage("a", "day", requests=1, prompt_tokens=10, completion_tokens=5, cost_usd=0.01)
    u = await store.add_usage("a", "day", requests=1, prompt_tokens=10)
    assert u.requests == 2 and u.tokens == 25 and abs(u.cost_usd - 0.01) < 1e-9
    assert (await store.get_usage("b", "day")).requests == 0


async def test_usage_resets_in_next_window():
    clock = Clock(t=60 * 1000)  # start of a minute
    store = InMemoryStore(clock=clock)
    await store.add_usage("a", "minute", requests=5)
    clock.t += 59
    assert (await store.get_usage("a", "minute")).requests == 5
    clock.t += 1
    assert (await store.get_usage("a", "minute")).requests == 0
    assert all(v.requests == 0 for v in (await store.all_usage()).values())


def test_window_bucket():
    key, expires = window_bucket("hour", now=3600 * 5 + 10)
    assert key == "hour:5" and expires == 3600 * 6

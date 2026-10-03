"""In-process StateStore. Single event loop and no awaits inside operations, so each
operation is atomic without locks. State is lost on restart (budgets included)."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import replace

from aicl.state.base import SessionState, ToolCallRecord, UsageCounters, Window, window_bucket

MAX_TOOL_CALLS_KEPT = 256
_SWEEP_EVERY = 1000  # operations between expiry sweeps


class InMemoryStore:
    def __init__(self, session_ttl_seconds: float = 3600, clock=time.time):
        self.session_ttl = session_ttl_seconds
        self._clock = clock
        self._sessions: dict[str, SessionState] = {}
        self._calls: dict[str, deque[ToolCallRecord]] = {}
        self._last_seen: dict[str, float] = {}
        self._usage: dict[tuple[str, str], UsageCounters] = {}
        self._usage_expiry: dict[tuple[str, str], float] = {}
        self._ops = 0

    # --- sessions ---

    def _session(self, session_id: str) -> SessionState:
        now = self._clock()
        self._tick(now)
        last = self._last_seen.get(session_id)
        if last is not None and now - last > self.session_ttl:
            self._drop_session(session_id)
        self._last_seen[session_id] = now
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
            self._calls[session_id] = deque(maxlen=MAX_TOOL_CALLS_KEPT)
        return self._sessions[session_id]

    def _drop_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._calls.pop(session_id, None)
        self._last_seen.pop(session_id, None)

    async def get_session(self, session_id: str) -> SessionState:
        s = self._session(session_id)
        # Return a copy: callers must go through the store to change state.
        return replace(s, taint_sources=list(s.taint_sources), tool_calls=list(self._calls[session_id]))

    async def mark_tainted(self, session_id: str, source: str) -> None:
        s = self._session(session_id)
        s.tainted = True
        if source not in s.taint_sources:
            s.taint_sources.append(source)

    async def record_tool_call(self, session_id: str, tool: str, args_hash: str) -> list[ToolCallRecord]:
        self._session(session_id)
        calls = self._calls[session_id]
        calls.append(ToolCallRecord(tool=tool, args_hash=args_hash, ts=self._clock()))
        return list(calls)

    async def set_delegation_depth(self, session_id: str, depth: int) -> None:
        self._session(session_id).delegation_depth = depth

    # --- budgets ---

    def _counters(self, identity: str, window: Window) -> UsageCounters:
        now = self._clock()
        self._tick(now)
        bucket, expires_at = window_bucket(window, now)
        key = (identity, bucket)
        if key not in self._usage:
            self._usage[key] = UsageCounters()
            self._usage_expiry[key] = expires_at
        return self._usage[key]

    async def get_usage(self, identity: str, window: Window) -> UsageCounters:
        return replace(self._counters(identity, window))

    async def add_usage(
        self,
        identity: str,
        window: Window,
        *,
        requests: int = 0,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float = 0.0,
        compute_seconds: float = 0.0,
    ) -> UsageCounters:
        c = self._counters(identity, window)
        c.requests += requests
        c.prompt_tokens += prompt_tokens
        c.completion_tokens += completion_tokens
        c.cost_usd += cost_usd
        c.compute_seconds += compute_seconds
        return replace(c)

    async def all_usage(self) -> dict[tuple[str, str], UsageCounters]:
        self._sweep(self._clock())
        return {k: replace(v) for k, v in self._usage.items()}

    async def reset(self) -> None:
        self._sessions.clear()
        self._calls.clear()
        self._last_seen.clear()
        self._usage.clear()
        self._usage_expiry.clear()

    # --- expiry ---

    def _tick(self, now: float) -> None:
        self._ops += 1
        if self._ops % _SWEEP_EVERY == 0:
            self._sweep(now)

    def _sweep(self, now: float) -> None:
        for sid in [s for s, t in self._last_seen.items() if now - t > self.session_ttl]:
            self._drop_session(sid)
        for key in [k for k, exp in self._usage_expiry.items() if exp <= now]:
            self._usage.pop(key, None)
            self._usage_expiry.pop(key, None)

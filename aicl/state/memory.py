"""In-process StateStore. Single event loop and no awaits inside operations, so each
operation is atomic without locks. State is lost on restart (budgets included)."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, replace

from aicl.state.base import (
    BudgetLimits,
    ReserveResult,
    SessionState,
    ToolCallRecord,
    UsageCounters,
    Window,
    window_bucket,
)

MAX_TOOL_CALLS_KEPT = 256
_SWEEP_EVERY = 1000  # operations between expiry sweeps


@dataclass
class Reservation:
    request_id: str
    identity: str
    window: Window
    bucket_key: str
    tokens: int
    cost_usd: float
    created_at: float
    expires_at: float


class InMemoryStore:
    def __init__(self, session_ttl_seconds: float = 3600, clock=time.time):
        self.session_ttl = session_ttl_seconds
        self._clock = clock
        self._lock = asyncio.Lock()
        self._sessions: dict[str, SessionState] = {}
        self._calls: dict[str, deque[ToolCallRecord]] = {}
        self._last_seen: dict[str, float] = {}
        self._usage: dict[tuple[str, str], UsageCounters] = {}
        self._usage_expiry: dict[tuple[str, str], float] = {}
        self._reservations: dict[str, Reservation] = {}
        self._rpm_timestamps: dict[str, deque[float]] = {}
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

    async def check_and_reserve(
        self,
        identity: str,
        window: Window,
        request_id: str,
        *,
        tokens: int,
        cost_usd: float,
        limits: BudgetLimits,
    ) -> ReserveResult:
        async with self._lock:
            now = self._clock()
            self._sweep(now)
            self._sweep_reservations(now)

            # 1. Rate limit (sliding window of 60 seconds)
            ts_queue = self._rpm_timestamps.setdefault(identity, deque())
            cutoff = now - 60.0
            while ts_queue and ts_queue[0] <= cutoff:
                ts_queue.popleft()

            # For backward compatibility with tests directly seeding add_usage(..., "minute")
            min_counters = self._counters(identity, "minute")
            current_rpm = max(len(ts_queue), min_counters.requests)

            if limits.max_requests_per_minute is not None and current_rpm >= limits.max_requests_per_minute:
                oldest = ts_queue[0] if ts_queue else now - 30.0
                retry_after = max(1.0, (oldest + 60.0) - now)
                return ReserveResult(
                    allowed=False,
                    exceeded_limit="rpm",
                    current_value=float(current_rpm),
                    limit_value=float(limits.max_requests_per_minute),
                    retry_after_s=retry_after,
                )

            # 2. Token limit
            bucket, bucket_exp = window_bucket(window, now)
            key = (identity, bucket)
            counters = self._usage.get(key, UsageCounters())
            reserved_tokens = sum(
                r.tokens
                for r in self._reservations.values()
                if r.identity == identity and r.bucket_key == bucket
            )
            total_tokens = counters.tokens + reserved_tokens + tokens
            if limits.max_tokens is not None and total_tokens > limits.max_tokens:
                retry_after = max(1.0, bucket_exp - now)
                return ReserveResult(
                    allowed=False,
                    exceeded_limit="tokens",
                    current_value=float(counters.tokens + reserved_tokens),
                    limit_value=float(limits.max_tokens),
                    retry_after_s=retry_after,
                )

            # 3. Cost limit
            reserved_cost = sum(
                r.cost_usd
                for r in self._reservations.values()
                if r.identity == identity and r.bucket_key == bucket
            )
            total_cost = counters.cost_usd + reserved_cost + cost_usd
            if limits.max_cost_usd is not None and total_cost > limits.max_cost_usd:
                retry_after = max(1.0, bucket_exp - now)
                return ReserveResult(
                    allowed=False,
                    exceeded_limit="cost",
                    current_value=counters.cost_usd + reserved_cost,
                    limit_value=limits.max_cost_usd,
                    retry_after_s=retry_after,
                )

            # 4. Compute limit
            if (
                limits.max_compute_seconds is not None
                and counters.compute_seconds >= limits.max_compute_seconds
            ):
                retry_after = max(1.0, bucket_exp - now)
                return ReserveResult(
                    allowed=False,
                    exceeded_limit="compute",
                    current_value=counters.compute_seconds,
                    limit_value=limits.max_compute_seconds,
                    retry_after_s=retry_after,
                )

            # All checks pass: record reservation and increment sliding RPM + requests
            ts_queue.append(now)
            min_counters.requests = max(min_counters.requests + 1, len(ts_queue))
            if window != "minute":
                c = self._counters(identity, window)
                c.requests += 1

            self._reservations[request_id] = Reservation(
                request_id=request_id,
                identity=identity,
                window=window,
                bucket_key=bucket,
                tokens=tokens,
                cost_usd=cost_usd,
                created_at=now,
                expires_at=now + 600.0,
            )
            return ReserveResult(allowed=True)

    async def settle(
        self,
        request_id: str,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float = 0.0,
        compute_seconds: float = 0.0,
    ) -> bool:
        async with self._lock:
            res = self._reservations.pop(request_id, None)
            if res is None:
                return False
            key = (res.identity, res.bucket_key)
            if key not in self._usage:
                self._usage[key] = UsageCounters()
            c = self._usage[key]
            c.prompt_tokens += prompt_tokens
            c.completion_tokens += completion_tokens
            c.cost_usd += cost_usd
            c.compute_seconds += compute_seconds
            return True

    async def all_usage(self) -> dict[tuple[str, str], UsageCounters]:
        self._sweep(self._clock())
        return {k: replace(v) for k, v in self._usage.items()}

    async def reset(self) -> None:
        self._sessions.clear()
        self._calls.clear()
        self._last_seen.clear()
        self._usage.clear()
        self._usage_expiry.clear()
        self._reservations.clear()
        self._rpm_timestamps.clear()

    # --- expiry ---

    def _sweep_reservations(self, now: float) -> None:
        expired = [rid for rid, r in self._reservations.items() if r.expires_at <= now]
        for rid in expired:
            self._reservations.pop(rid, None)

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

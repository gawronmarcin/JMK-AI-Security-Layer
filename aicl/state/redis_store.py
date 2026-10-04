"""Redis-backed StateStore: shared state for several gateway instances behind a load balancer.

Enabled with AICL_STATE_URL=redis://host:6379/0 (pip install -e ".[redis]"); without it the
gateway uses InMemoryStore. Same semantics as InMemoryStore:
- sessions slide their TTL on every touch; taint sources, delegation depth and the last
  MAX_TOOL_CALLS_KEPT tool calls live under `aicl:sess:{id}:*`;
- budget counters are hashes `aicl:usage:{identity}:{bucket}` updated with HINCRBY /
  HINCRBYFLOAT (atomic across instances) and expiring with their window bucket.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from aicl.state.base import (
    BudgetLimits,
    ReserveResult,
    SessionState,
    ToolCallRecord,
    UsageCounters,
    Window,
    window_bucket,
)
from aicl.state.memory import MAX_TOOL_CALLS_KEPT

PREFIX = "aicl"
_INT_FIELDS = ("requests", "prompt_tokens", "completion_tokens")
_FLOAT_FIELDS = ("cost_usd", "compute_seconds")


def _s(v: Any) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


class RedisStore:
    def __init__(self, client: Any, session_ttl_seconds: float = 3600, clock=time.time, prefix: str = PREFIX):
        self.r = client  # redis.asyncio.Redis (or a compatible fake in tests)
        self.session_ttl = int(session_ttl_seconds)
        self._clock = clock
        self.prefix = prefix

    @classmethod
    def from_url(cls, url: str, **kw: Any) -> RedisStore:
        import redis.asyncio as aioredis  # optional dependency: pip install -e ".[redis]"

        return cls(aioredis.from_url(url), **kw)

    # --- keys ---

    def _k(self, *parts: str) -> str:
        return ":".join((self.prefix, *parts))

    def _sess_keys(self, session_id: str) -> tuple[str, str, str]:
        base = self._k("sess", session_id)
        return base, f"{base}:taint", f"{base}:calls"

    async def _touch(self, session_id: str) -> None:
        pipe = self.r.pipeline(transaction=True)
        for key in self._sess_keys(session_id):
            pipe.expire(key, self.session_ttl)
        await pipe.execute()

    # --- sessions ---

    async def get_session(self, session_id: str) -> SessionState:
        meta_key, taint_key, calls_key = self._sess_keys(session_id)
        pipe = self.r.pipeline(transaction=True)
        pipe.hgetall(meta_key)
        pipe.lrange(taint_key, 0, -1)
        pipe.lrange(calls_key, 0, -1)
        meta, taint, calls = await pipe.execute()
        await self._touch(session_id)
        meta = {_s(k): _s(v) for k, v in (meta or {}).items()}
        return SessionState(
            session_id=session_id,
            tainted=meta.get("tainted") == "1",
            taint_sources=[_s(t) for t in taint],
            tool_calls=[ToolCallRecord(**json.loads(_s(c))) for c in calls],
            delegation_depth=int(meta.get("delegation_depth", 0)),
        )

    async def mark_tainted(self, session_id: str, source: str) -> None:
        meta_key, taint_key, _ = self._sess_keys(session_id)
        existing = [_s(t) for t in await self.r.lrange(taint_key, 0, -1)]
        pipe = self.r.pipeline(transaction=True)
        pipe.hset(meta_key, mapping={"tainted": "1"})
        if source not in existing:
            pipe.rpush(taint_key, source)
        await pipe.execute()
        await self._touch(session_id)

    async def record_tool_call(self, session_id: str, tool: str, args_hash: str) -> list[ToolCallRecord]:
        _, _, calls_key = self._sess_keys(session_id)
        rec = json.dumps({"tool": tool, "args_hash": args_hash, "ts": self._clock()})
        pipe = self.r.pipeline(transaction=True)
        pipe.rpush(calls_key, rec)
        pipe.ltrim(calls_key, -MAX_TOOL_CALLS_KEPT, -1)
        pipe.lrange(calls_key, 0, -1)
        *_, calls = await pipe.execute()
        await self._touch(session_id)
        return [ToolCallRecord(**json.loads(_s(c))) for c in calls]

    async def set_delegation_depth(self, session_id: str, depth: int) -> None:
        meta_key, _, _ = self._sess_keys(session_id)
        await self.r.hset(meta_key, mapping={"delegation_depth": str(depth)})
        await self._touch(session_id)

    # --- budgets ---

    @staticmethod
    def _counters(raw: dict[Any, Any] | None) -> UsageCounters:
        d = {_s(k): _s(v) for k, v in (raw or {}).items()}
        return UsageCounters(
            requests=int(d.get("requests", 0)),
            prompt_tokens=int(d.get("prompt_tokens", 0)),
            completion_tokens=int(d.get("completion_tokens", 0)),
            cost_usd=float(d.get("cost_usd", 0.0)),
            compute_seconds=float(d.get("compute_seconds", 0.0)),
        )

    def _usage_key(self, identity: str, window: Window) -> tuple[str, float]:
        bucket, expires_at = window_bucket(window, self._clock())
        return self._k("usage", identity, bucket), expires_at

    async def get_usage(self, identity: str, window: Window) -> UsageCounters:
        key, _ = self._usage_key(identity, window)
        return self._counters(await self.r.hgetall(key))

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
        key, expires_at = self._usage_key(identity, window)
        values = {"requests": requests, "prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                  "cost_usd": cost_usd, "compute_seconds": compute_seconds}
        pipe = self.r.pipeline(transaction=True)
        for f in _INT_FIELDS:
            pipe.hincrby(key, f, int(values[f]))
        for f in _FLOAT_FIELDS:
            pipe.hincrbyfloat(key, f, float(values[f]))
        pipe.expireat(key, int(expires_at))  # window buckets end on whole seconds
        pipe.hgetall(key)
        *_, raw = await pipe.execute()
        return self._counters(raw)

    async def _acquire_lock(self, identity: str, timeout: float = 5.0) -> bool:
        lock_key = self._k("lock", "budget", identity)
        deadline = self._clock() + timeout
        while self._clock() < deadline:
            res = await self.r.set(lock_key, "1", nx=True, ex=10)
            if res:
                return True
            await asyncio.sleep(0.01)
        return False

    async def _release_lock(self, identity: str) -> None:
        lock_key = self._k("lock", "budget", identity)
        await self.r.delete(lock_key)

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
        now = self._clock()
        await self._acquire_lock(identity)
        try:
            # 1. Rate limit (sliding window of 60 seconds)
            rpm_key = self._k("rpm", identity)
            raw_ts = await self.r.lrange(rpm_key, 0, -1)
            timestamps = []
            for t in raw_ts:
                try:
                    timestamps.append(float(_s(t)))
                except ValueError:
                    pass
            cutoff = now - 60.0
            filtered_ts = [t for t in timestamps if t > cutoff]

            min_key, min_exp = self._usage_key(identity, "minute")
            min_usage = self._counters(await self.r.hgetall(min_key))
            current_rpm = max(len(filtered_ts), min_usage.requests)

            if limits.max_requests_per_minute is not None and current_rpm >= limits.max_requests_per_minute:
                oldest = filtered_ts[0] if filtered_ts else now - 30.0
                retry_after = max(1.0, (oldest + 60.0) - now)
                return ReserveResult(
                    allowed=False,
                    exceeded_limit="rpm",
                    current_value=float(current_rpm),
                    limit_value=float(limits.max_requests_per_minute),
                    retry_after_s=retry_after,
                )

            # 2. Token & cost limits
            key, bucket_exp = self._usage_key(identity, window)
            counters = self._counters(await self.r.hgetall(key))

            bucket, _ = window_bucket(window, now)
            active_res_key = self._k("active_res", identity, bucket)
            raw_res_ids = await self.r.lrange(active_res_key, 0, -1)
            reserved_tokens = 0
            reserved_cost = 0.0
            valid_res_ids = []

            for r_id in raw_res_ids:
                s_id = _s(r_id)
                r_key = self._k("res", s_id)
                r_data = await self.r.hgetall(r_key)
                if r_data:
                    valid_res_ids.append(s_id)
                    d = {_s(k): _s(v) for k, v in r_data.items()}
                    reserved_tokens += int(d.get("tokens", 0))
                    reserved_cost += float(d.get("cost_usd", 0.0))

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

            # All checks pass: save reservation, increment requests & sliding window
            filtered_ts.append(now)
            pipe = self.r.pipeline(transaction=True)
            pipe.delete(rpm_key)
            if filtered_ts:
                pipe.rpush(rpm_key, *[str(t) for t in filtered_ts])
                pipe.expire(rpm_key, 120)

            pipe.hincrby(min_key, "requests", 1)
            pipe.expireat(min_key, int(min_exp))
            if key != min_key:
                pipe.hincrby(key, "requests", 1)
                pipe.expireat(key, int(bucket_exp))

            res_key = self._k("res", request_id)
            pipe.hset(
                res_key,
                mapping={
                    "identity": identity,
                    "window": window,
                    "bucket": bucket,
                    "tokens": str(tokens),
                    "cost_usd": str(cost_usd),
                    "created_at": str(now),
                },
            )
            pipe.expire(res_key, 600)

            # Update active reservations list
            valid_res_ids.append(request_id)
            pipe.delete(active_res_key)
            if valid_res_ids:
                pipe.rpush(active_res_key, *valid_res_ids)
                pipe.expire(active_res_key, 660)

            await pipe.execute()
            return ReserveResult(allowed=True)
        finally:
            await self._release_lock(identity)

    async def settle(
        self,
        request_id: str,
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        cost_usd: float = 0.0,
        compute_seconds: float = 0.0,
    ) -> bool:
        res_key = self._k("res", request_id)
        raw = await self.r.hgetall(res_key)
        if not raw:
            return False
        d = {_s(k): _s(v) for k, v in raw.items()}
        identity = d.get("identity")
        bucket = d.get("bucket")
        if not identity or not bucket:
            await self.r.delete(res_key)
            return False

        pipe = self.r.pipeline(transaction=True)
        pipe.delete(res_key)
        usage_key = self._k("usage", identity, bucket)
        pipe.hincrby(usage_key, "prompt_tokens", prompt_tokens)
        pipe.hincrby(usage_key, "completion_tokens", completion_tokens)
        pipe.hincrbyfloat(usage_key, "cost_usd", cost_usd)
        pipe.hincrbyfloat(usage_key, "compute_seconds", compute_seconds)
        await pipe.execute()
        return True

    async def all_usage(self) -> dict[tuple[str, str], UsageCounters]:
        out: dict[tuple[str, str], UsageCounters] = {}
        prefix = self._k("usage", "")
        async for key in self.r.scan_iter(match=f"{prefix}*"):
            name = _s(key)[len(prefix):]
            identity, _, bucket = name.partition(":")
            out[(identity, bucket)] = self._counters(await self.r.hgetall(key))
        return out

    async def reset(self) -> None:
        keys = [k async for k in self.r.scan_iter(match=self._k("*"))]
        if keys:
            await self.r.delete(*keys)

"""Redis-backed StateStore: shared state for several gateway instances behind a load balancer.

Enabled with AICL_STATE_URL=redis://host:6379/0 (pip install -e ".[redis]"); without it the
gateway uses InMemoryStore. Same semantics as InMemoryStore:
- sessions slide their TTL on every touch; taint sources, delegation depth and the last
  MAX_TOOL_CALLS_KEPT tool calls live under `aicl:sess:{id}:*`;
- budget counters are hashes `aicl:usage:{identity}:{bucket}` updated with HINCRBY /
  HINCRBYFLOAT (atomic across instances) and expiring with their window bucket.
"""

from __future__ import annotations

import json
import time
from typing import Any

from aicl.state.base import SessionState, ToolCallRecord, UsageCounters, Window, window_bucket
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

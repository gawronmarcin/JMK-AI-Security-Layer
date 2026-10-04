"""In-memory stand-in for the Redis commands aicl uses (no server, no redis package needed).

`FakeRedis` mimics redis.Redis (sync), `FakeAsyncRedis` redis.asyncio.Redis. Several clients can
share one `Data` - like several gateway instances talking to one Redis. Expiry follows `clock`.
Values come back as str (real clients return bytes; the stores accept both).
"""

from __future__ import annotations

import fnmatch
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any


class Data:
    def __init__(self, clock: Callable[[], float] = time.time):
        self.kv: dict[str, Any] = {}
        self.exp: dict[str, float] = {}
        self.clock = clock

    def alive(self, key: str) -> bool:
        e = self.exp.get(key)
        if e is not None and self.clock() >= e:
            self.kv.pop(key, None)
            self.exp.pop(key, None)
        return key in self.kv


def _slice(items: list[Any], start: int, stop: int) -> list[Any]:
    n = len(items)
    s = start if start >= 0 else max(n + start, 0)
    e = stop if stop >= 0 else n + stop
    return items[s:e + 1]


class FakeRedis:
    def __init__(self, data: Data | None = None):
        self.d = data or Data()

    # --- strings
    def get(self, key: str) -> Any:
        return self.d.kv[key] if self.d.alive(key) else None

    def set(self, key: str, value: Any, nx: bool = False, ex: int | None = None) -> bool | None:
        if nx and self.d.alive(key):
            return None
        self.d.kv[key] = str(value)
        if ex:
            self.d.exp[key] = self.d.clock() + ex
        else:
            self.d.exp.pop(key, None)
        return True

    def delete(self, *keys: str) -> int:
        n = 0
        for k in keys:
            if self.d.alive(k):
                del self.d.kv[k]
                self.d.exp.pop(k, None)
                n += 1
        return n

    def expire(self, key: str, seconds: int) -> bool:
        if not self.d.alive(key):
            return False
        self.d.exp[key] = self.d.clock() + seconds
        return True

    def expireat(self, key: str, when: int) -> bool:
        if not self.d.alive(key):
            return False
        self.d.exp[key] = float(when)
        return True

    # --- hashes
    def _hash(self, key: str) -> dict[str, str]:
        if not self.d.alive(key):
            self.d.kv[key] = {}
        return self.d.kv[key]

    def hset(self, key: str, mapping: dict[str, Any]) -> int:
        h = self._hash(key)
        h.update({k: str(v) for k, v in mapping.items()})
        return len(mapping)

    def hgetall(self, key: str) -> dict[str, str]:
        return dict(self.d.kv[key]) if self.d.alive(key) else {}

    def hincrby(self, key: str, field: str, amount: int) -> int:
        h = self._hash(key)
        h[field] = str(int(h.get(field, "0")) + amount)
        return int(h[field])

    def hincrbyfloat(self, key: str, field: str, amount: float) -> float:
        h = self._hash(key)
        h[field] = repr(float(h.get(field, "0")) + amount)
        return float(h[field])

    # --- lists
    def _list(self, key: str) -> list[str]:
        if not self.d.alive(key):
            self.d.kv[key] = []
        return self.d.kv[key]

    def rpush(self, key: str, *values: Any) -> int:
        lst = self._list(key)
        lst.extend(str(v) for v in values)
        return len(lst)

    def ltrim(self, key: str, start: int, stop: int) -> bool:
        if self.d.alive(key):
            self.d.kv[key] = _slice(self.d.kv[key], start, stop)
        return True

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        return _slice(self.d.kv[key], start, stop) if self.d.alive(key) else []

    # --- sorted sets
    def zadd(self, key: str, mapping: dict[str, float]) -> int:
        z = self.d.kv.setdefault(key, {}) if self.d.alive(key) else self.d.kv.setdefault(key, {})
        z.update(mapping)
        return len(mapping)

    def zrevrange(self, key: str, start: int, stop: int) -> list[str]:
        if not self.d.alive(key):
            return []
        ordered = [m for m, _ in sorted(self.d.kv[key].items(), key=lambda kv: -kv[1])]
        return _slice(ordered, start, stop)

    # --- keys
    def scan_iter(self, match: str = "*") -> Iterator[str]:
        for key in list(self.d.kv):
            if self.d.alive(key) and fnmatch.fnmatchcase(key, match):
                yield key

    def pipeline(self, transaction: bool = True) -> _Pipeline:
        return _Pipeline(self)


class _Pipeline:
    def __init__(self, client: FakeRedis):
        self._client = client
        self._ops: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Callable[..., _Pipeline]:
        def queue(*args: Any, **kwargs: Any) -> _Pipeline:
            self._ops.append((name, args, kwargs))
            return self

        return queue

    def run(self) -> list[Any]:
        return [getattr(self._client, name)(*a, **kw) for name, a, kw in self._ops]

    def execute(self) -> list[Any]:
        return self.run()


class _AsyncPipeline(_Pipeline):
    async def execute(self) -> list[Any]:  # type: ignore[override]
        return self.run()


class FakeAsyncRedis:
    def __init__(self, data: Data | None = None):
        self._sync = FakeRedis(data)
        self.d = self._sync.d

    def __getattr__(self, name: str) -> Callable[..., Any]:
        fn = getattr(self._sync, name)

        async def call(*args: Any, **kwargs: Any) -> Any:
            return fn(*args, **kwargs)

        return call

    def pipeline(self, transaction: bool = True) -> _AsyncPipeline:
        return _AsyncPipeline(self._sync)

    async def scan_iter(self, match: str = "*") -> AsyncIterator[str]:
        for key in self._sync.scan_iter(match=match):
            yield key

"""StateStore interface: everything that must survive between requests (§5.4).

Async on purpose, even though InMemoryStore does no I/O: a RedisStore can then be
swapped in for horizontal scaling without touching callers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal, Protocol

Window = Literal["minute", "hour", "day"]
_WINDOW_SECONDS: dict[str, int] = {"minute": 60, "hour": 3600, "day": 86400}


@dataclass(frozen=True)
class ToolCallRecord:
    tool: str
    args_hash: str
    ts: float


@dataclass
class SessionState:
    session_id: str
    tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    delegation_depth: int = 0


@dataclass
class UsageCounters:
    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    compute_seconds: float = 0.0

    @property
    def tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def window_bucket(window: Window, now: float | None = None) -> tuple[str, float]:
    """Fixed-window bucket: ("day:20364", expires_at). UTC-aligned."""
    now = time.time() if now is None else now
    size = _WINDOW_SECONDS[window]
    index = int(now // size)
    return f"{window}:{index}", (index + 1) * size


class StateStore(Protocol):
    # Sessions (TTL-evicted)
    async def get_session(self, session_id: str) -> SessionState: ...
    async def mark_tainted(self, session_id: str, source: str) -> None: ...
    async def record_tool_call(self, session_id: str, tool: str, args_hash: str) -> list[ToolCallRecord]:
        """Append a call and return the session's recent calls, oldest first."""
        ...

    async def set_delegation_depth(self, session_id: str, depth: int) -> None: ...

    # Budgets, keyed by (identity, window bucket)
    async def get_usage(self, identity: str, window: Window) -> UsageCounters: ...
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
    ) -> UsageCounters: ...

    async def all_usage(self) -> dict[tuple[str, str], UsageCounters]:
        """Current counters per (identity, bucket key), for /admin/metrics/budgets."""
        ...

    async def reset(self) -> None: ...

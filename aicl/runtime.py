"""Runtime: everything a flow needs to handle a request, created once per app."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from aicl.audit import AuditWriter, new_event
from aicl.engine import missing_controls
from aicl.feeds import FeedStore
from aicl.models import Control
from aicl.policy.schema import CompiledPolicy
from aicl.proxy import UpstreamClient
from aicl.state import StateStore


@dataclass
class Runtime:
    policy: CompiledPolicy  # swapped atomically on hot reload; read once per request
    env: Mapping[str, str]
    state: StateStore
    audit: AuditWriter
    upstream: UpstreamClient
    feeds: FeedStore
    controls: Mapping[str, Control] | None = None  # None = the global registry
    _started: bool = field(default=False, repr=False)

    async def start(self) -> None:
        await self.audit.start()
        await self.upstream.start()
        self.feeds.on_event = self._feed_event
        self.feeds.configure(self.policy.raw.signature_feeds, force=True)
        self.audit.emit(
            new_event(
                "policy.reloaded",
                policy_version=self.policy.version,
                detail={
                    "reason": "startup",
                    "warnings": list(self.policy.warnings),
                    "missing_controls": missing_controls(self.policy, self.controls),
                },
            )
        )
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        await self.upstream.stop()
        await self.audit.stop()
        self._started = False

    def _feed_event(self, detail: dict, error: str | None) -> None:
        self.audit.emit(
            new_event("feed.reloaded", feed_version=detail.get("feed_version"), detail=detail, error=error)
        )

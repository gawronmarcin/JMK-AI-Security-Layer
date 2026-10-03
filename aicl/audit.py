"""Append-only audit log (ARCHITECTURE.md §8).

One JSON object per line in audit.jsonl. Requests only enqueue events (`emit`); a
single background task serializes and writes them, so logging never blocks a response
and lines never interleave. Listeners (e.g. the live metrics aggregator) get every
event in-process without tailing the file.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from aicl.models import AuditEvent, EventType
from aicl.utils import new_id, utc_now_iso

log = logging.getLogger(__name__)

Listener = Callable[[AuditEvent], None]


def new_event(type: EventType, **fields: Any) -> AuditEvent:
    return AuditEvent(ts=utc_now_iso(), event_id=new_id("evt"), type=type, **fields)


def serialize(event: AuditEvent, max_bytes: int) -> str:
    """JSON line within max_bytes: drops match excerpts, then reasons, then all decisions."""
    line = event.model_dump_json()
    if len(line.encode()) <= max_bytes:
        return line
    data = json.loads(line)
    for d in data["decisions"]:
        d["matches"] = d["matches"][:1]
    data["error"] = (data["error"] or "") + " [event truncated]"
    for step in ("trim_reasons", "drop_decisions"):
        line = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        if len(line.encode()) <= max_bytes:
            return line
        if step == "trim_reasons":
            for d in data["decisions"]:
                d["reason"] = d["reason"][:200]
        else:
            data["decisions"] = [
                {"control_id": d["control_id"], "threat_ids": d["threat_ids"], "action": d["action"]}
                for d in data["decisions"]
            ]
    data["detail"] = None
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


class AuditWriter:
    def __init__(self, path: str | Path, max_event_bytes: int = 65536):
        self.path = Path(path)
        self.max_event_bytes = max_event_bytes
        self._queue: asyncio.Queue[AuditEvent | None] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._listeners: list[Listener] = []
        self._recent: list[AuditEvent] = []

    def recent_events(self) -> list[AuditEvent]:
        return list(self._recent)

    def add_listener(self, fn: Listener) -> None:
        self._listeners.append(fn)

    def emit(self, event: AuditEvent) -> None:
        """Non-blocking; safe to call from request handlers."""
        self._recent.append(event)
        if len(self._recent) > 1000:
            self._recent.pop(0)
        for fn in self._listeners:
            try:
                fn(event)
            except Exception:  # a broken listener must not break requests or the log
                log.exception("audit listener failed")
        self._queue.put_nowait(event)

    async def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._task = asyncio.create_task(self._run(), name="aicl-audit-writer")

    async def stop(self) -> None:
        """Flush everything queued so far, then stop."""
        if self._task is None:
            return
        self._queue.put_nowait(None)
        await self._task
        self._task = None

    async def _run(self) -> None:
        while True:
            batch = [await self._queue.get()]
            while not self._queue.empty():
                batch.append(self._queue.get_nowait())
            stop = None in batch
            lines = [serialize(e, self.max_event_bytes) for e in batch if e is not None]
            if lines:
                try:
                    await asyncio.to_thread(self._append, lines)
                except OSError:
                    log.exception("audit write failed, %d events lost", len(lines))
            if stop:
                return

    def _append(self, lines: list[str]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


def iter_events(path: str | Path) -> Iterator[AuditEvent]:
    """Read events back (metrics rebuild on startup, replay, tests). Skips corrupt lines."""
    p = Path(path)
    if not p.exists():
        return
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield AuditEvent.model_validate_json(line)
            except ValueError:
                log.warning("skipping unreadable audit line")

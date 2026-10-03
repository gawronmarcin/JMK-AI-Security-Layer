"""Runtime: everything a flow needs to handle a request, created once per app.

Hot reload (§9): a background task polls the policy file and the feed files (mtime + size)
every `reload_interval` seconds. Polling instead of file-system events works the same on
Docker bind mounts and with editors that save by renaming a temp file. A changed policy is
parsed, validated and swapped in atomically: requests already running keep the policy they
started with, the next request sees the new one. An invalid file leaves the old policy
active and emits `policy.rejected`. `reload_policy()` is also the manual reload entry point.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from aicl.approvals import ApprovalStore
from aicl.audit import AuditWriter, new_event
from aicl.engine import missing_controls
from aicl.feeds import FeedStore
from aicl.models import Control
from aicl.policy.loader import PolicyError, parse_policy
from aicl.policy.schema import CompiledPolicy
from aicl.proxy import UpstreamClient
from aicl.state import StateStore
from aicl.utils import utc_now_iso

log = logging.getLogger(__name__)

# Called with the new policy at startup and after every successful reload.
PolicyListener = Callable[[CompiledPolicy], None]

_FileSig = tuple[int, int] | None  # (mtime_ns, size); None = missing


def _sig(path: Path) -> _FileSig:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


@dataclass
class Runtime:
    policy: CompiledPolicy  # swapped atomically on hot reload; read once per request
    env: Mapping[str, str]
    state: StateStore
    audit: AuditWriter
    upstream: UpstreamClient
    feeds: FeedStore
    controls: Mapping[str, Control] | None = None  # None = the global registry
    policy_path: Path | None = None  # None = no hot reload
    reload_interval: float | None = 1.0  # seconds between file checks; None = no watcher
    policy_listeners: list[PolicyListener] = field(default_factory=list)
    approvals: ApprovalStore = field(default_factory=ApprovalStore)
    _started: bool = field(default=False, repr=False)
    _watcher: asyncio.Task[None] | None = field(default=None, repr=False)
    _sigs: dict[Path, _FileSig] = field(default_factory=dict, repr=False)
    # Outcome of the latest load/reload attempt, for /admin/policy: {at, result, reason, error}.
    last_reload: dict[str, str | None] = field(default_factory=dict)

    async def start(self) -> None:
        await self.audit.start()
        await self.upstream.start()
        self.feeds.on_event = self._feed_event
        self.feeds.configure(self.policy.raw.signature_feeds, force=True)
        listener_errors = self._notify(self.policy)
        self._emit_reloaded(self.policy, {"reason": "startup"}, listener_errors)
        self._record_reload("reloaded", "startup")
        self._sigs = self._snapshot()
        if self.policy_path is not None and self.reload_interval:
            self._watcher = asyncio.create_task(self._watch(self.reload_interval), name="aicl-reload-watcher")
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        if self._watcher is not None:
            self._watcher.cancel()
            try:
                await self._watcher
            except asyncio.CancelledError:
                pass
            self._watcher = None
        await self.upstream.stop()
        await self.audit.stop()
        self._started = False

    # --- reload -----------------------------------------------------------------------------

    def reload_policy(self, reason: str = "file_changed") -> bool:
        """Reload the policy file. True if a new policy was swapped in."""
        if self.policy_path is None:
            return False
        try:
            source = self.policy_path.read_text(encoding="utf-8")
            new = parse_policy(source, self.env)
        except (OSError, PolicyError) as exc:
            errors = (
                exc.errors if isinstance(exc, PolicyError) else [f"cannot read policy: {type(exc).__name__}"]
            )
            log.warning("policy rejected, keeping %s: %s", self.policy.version, "; ".join(errors))
            self.audit.emit(
                new_event(
                    "policy.rejected",
                    policy_version=self.policy.version,  # the version that stays active
                    detail={"reason": reason, "path": str(self.policy_path), "errors": errors},
                    error="invalid policy, previous version kept",
                )
            )
            self._record_reload("rejected", reason, "; ".join(errors))
            return False
        if new.version == self.policy.version:
            self._record_reload("ok (unchanged)", reason)
            return False  # touched but unchanged

        old = self.policy
        self.policy = new  # atomic swap: one attribute assignment
        self.feeds.configure(new.raw.signature_feeds)
        listener_errors = self._notify(new)
        detail = {
            "reason": reason,
            "previous_version": old.version,
            # §6.3: a control removed from the file is disabled, with a warning.
            "removed_controls": sorted(set(old.raw.controls) - set(new.raw.controls)),
        }
        self._emit_reloaded(new, detail, listener_errors)
        self._record_reload("reloaded", reason)
        return True

    def _record_reload(self, result: str, reason: str, error: str | None = None) -> None:
        self.last_reload = {"at": utc_now_iso(), "result": result, "reason": reason, "error": error}

    def check_files(self) -> None:
        """One watcher pass: reload whatever changed since the last pass."""
        current = self._snapshot()
        if self.policy_path is not None and current.get(self.policy_path) != self._sigs.get(self.policy_path):
            self.reload_policy()
        for path in self.feeds.paths():
            if current.get(path) != self._sigs.get(path):
                self.feeds.reload_path(path)
        self._sigs = self._snapshot()  # feed paths may have changed with the policy

    async def _watch(self, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                self.check_files()
            except Exception:
                log.exception("hot reload check failed")

    def _snapshot(self) -> dict[Path, _FileSig]:
        paths = list(self.feeds.paths())
        if self.policy_path is not None:
            paths.append(self.policy_path)
        return {p: _sig(p) for p in paths}

    # --- events -----------------------------------------------------------------------------

    def _notify(self, policy: CompiledPolicy) -> list[str]:
        errors = []
        for listener in self.policy_listeners:
            try:
                listener(policy)
            except Exception as exc:
                log.exception("policy listener failed")
                errors.append(f"{getattr(listener, '__name__', 'listener')}: {type(exc).__name__}")
        return errors

    def _emit_reloaded(self, policy: CompiledPolicy, detail: dict, listener_errors: list[str]) -> None:
        detail = detail | {
            "warnings": list(policy.warnings),
            "missing_controls": missing_controls(policy, self.controls),
        }
        if listener_errors:
            detail["listener_errors"] = listener_errors
        self.audit.emit(new_event("policy.reloaded", policy_version=policy.version, detail=detail))

    def _feed_event(self, detail: dict, error: str | None) -> None:
        self.audit.emit(
            new_event("feed.reloaded", feed_version=detail.get("feed_version"), detail=detail, error=error)
        )

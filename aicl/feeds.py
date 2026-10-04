"""Signature feeds: externally managed historical-attack signatures (ARCHITECTURE.md §6.8).

Feeds live outside the policy so an external system can update them. The policy's
`signature_feeds` list says which feeds to load.

    store.configure(policy.raw.signature_feeds)   # R1: at startup and on every policy swap
    store.reload()                                # R1: from the file watcher (no watcher in here)
    snap = feeds.current()                        # controls and flows: immutable snapshot
    for sig in snap.for_set("artifact"): ...
    snap.regex("SIG-INJ-001")                     # precompiled pattern for kind=regex

A feed that fails to load keeps its last good version (`on_unavailable: keep_last_good`)
or contributes nothing (`empty`). Every load or failure is reported through `on_event`,
which R1 wires to the audit log as a `feed.reloaded` event.

Known limitation: a reload between two controls of the same request can show them
different versions; the audit records the version read at request start.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aicl.models import Severity
from aicl.policy.schema import FeedRef
from aicl.utils import utc_now_iso

log = logging.getLogger(__name__)

SignatureSet = Literal["injection", "artifact", "code_exec", "supply_chain", "exfil"]
SignatureKind = Literal["regex", "pickle_global", "package", "model_repo", "url_pattern", "sha256"]

_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")
MAX_FEED_BYTES = 5 * 1024 * 1024  # 5 MB max feed size

# (detail, error): error is None on success.
FeedEventHandler = Callable[[dict[str, Any], str | None], None]


# --- File format (CONTRACT: §6.8 entry shape) ---------------------------------------------------


class Signature(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    set: SignatureSet
    kind: SignatureKind
    pattern: str = Field(min_length=1)  # meaning depends on kind
    severity: Severity
    description: str = ""
    refs: list[str] = Field(default_factory=list)
    added: str | None = None

    @model_validator(mode="after")
    def _pattern_matches_kind(self) -> Signature:
        if self.kind == "regex":
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex: {exc}") from exc
        elif self.kind == "sha256" and not _SHA256_RE.fullmatch(self.pattern):
            raise ValueError("sha256 pattern must be 64 hex characters")
        return self


class FeedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feed_version: str = Field(min_length=1)
    signatures: list[Signature] = Field(default_factory=list)

    @field_validator("feed_version", mode="before")
    @classmethod
    def _version_as_text(cls, v: Any) -> Any:
        # YAML turns an unquoted 2026.1 into a float; keep the version textual.
        return str(v) if isinstance(v, int | float) else v

    @model_validator(mode="after")
    def _unique_ids(self) -> FeedFile:
        seen: set[str] = set()
        dupes = sorted({s.id for s in self.signatures if s.id in seen or seen.add(s.id)})  # type: ignore[func-returns-value]
        if dupes:
            raise ValueError(f"duplicate signature ids: {', '.join(dupes)}")
        return self


class FeedError(ValueError):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("; ".join(errors))


def parse_feed(source: str) -> FeedFile:
    try:
        data = yaml.safe_load(source)
    except yaml.YAMLError as exc:
        raise FeedError([f"YAML syntax: {exc}"]) from exc
    if not isinstance(data, dict):
        raise FeedError(["<root>: feed must be a YAML mapping"])
    try:
        return FeedFile.model_validate(data)
    except ValidationError as exc:
        raise FeedError(
            [
                f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg'].removeprefix('Value error, ')}"
                for e in exc.errors()
            ]
        ) from exc


# --- Runtime snapshot -------------------------------------------------------------------------


@dataclass(frozen=True)
class FeedSnapshot:
    """Read-only view of all loaded feeds. Build once per load, share freely."""

    version: str | None  # what goes into the audit event's feed_version
    sources: Mapping[str, str]  # feed name -> feed_version
    signatures: tuple[Signature, ...] = ()
    _by_set: Mapping[str, tuple[Signature, ...]] = field(default_factory=dict, repr=False)
    _regex: Mapping[str, re.Pattern[str]] = field(default_factory=dict, repr=False)

    def for_set(self, name: str) -> tuple[Signature, ...]:
        return self._by_set.get(name, ())

    def regex(self, signature_id: str) -> re.Pattern[str] | None:
        return self._regex.get(signature_id)


EMPTY = FeedSnapshot(version=None, sources={})


def build_snapshot(feeds: Mapping[str, FeedFile]) -> FeedSnapshot:
    """Merge feeds in name order. On a signature id clash the first feed wins."""
    if not feeds:
        return EMPTY
    sigs: list[Signature] = []
    seen: set[str] = set()
    for name in sorted(feeds):
        for sig in feeds[name].signatures:
            if sig.id in seen:
                log.warning("signature %s in feed %s shadowed by an earlier feed", sig.id, name)
                continue
            seen.add(sig.id)
            sigs.append(sig)
    by_set: dict[str, list[Signature]] = {}
    for sig in sigs:
        by_set.setdefault(sig.set, []).append(sig)
    sources = {name: feeds[name].feed_version for name in sorted(feeds)}
    # Single feed: its own version (matches §8). Several: "name@version" joined.
    version = (
        next(iter(sources.values()))
        if len(sources) == 1
        else "+".join(f"{n}@{v}" for n, v in sources.items())
    )
    return FeedSnapshot(
        version=version,
        sources=sources,
        signatures=tuple(sigs),
        _by_set={k: tuple(v) for k, v in by_set.items()},
        _regex={s.id: re.compile(s.pattern) for s in sigs if s.kind == "regex"},
    )


# --- Store ------------------------------------------------------------------------------------


@dataclass
class FeedMeta:
    name: str
    source: Literal["file", "url"]
    path_or_url: str
    status: str = "pending"  # "loaded", "rejected", "not_modified"
    feed_version: str | None = None
    signatures_count: int = 0
    etag: str | None = None
    last_modified: str | None = None
    last_fetched_at: str | None = None
    last_error: str | None = None


class FeedStore:
    def __init__(
        self,
        base_dir: str | Path | None = None,
        on_event: FeedEventHandler | None = None,
        env: Mapping[str, str] | None = None,
    ):
        self.base_dir = Path.cwd() if base_dir is None else Path(base_dir)
        self.on_event = on_event
        self.env = env
        self._refs: dict[str, FeedRef] = {}
        self._good: dict[str, FeedFile] = {}  # last good version per feed name
        self._meta: dict[str, FeedMeta] = {}
        self._last_poll: dict[str, float] = {}
        self._snapshot = EMPTY

    def current(self) -> FeedSnapshot:
        return self._snapshot

    def paths(self) -> list[Path]:
        """Local feed files, for the watcher."""
        return [self._resolve(r.path) for r in self._refs.values() if r.path is not None]

    def feed_metadata(self) -> dict[str, dict[str, Any]]:
        return {
            name: {
                "name": m.name,
                "source": m.source,
                "path_or_url": m.path_or_url,
                "status": m.status,
                "feed_version": m.feed_version,
                "signatures": m.signatures_count,
                "last_fetched_at": m.last_fetched_at,
                "last_error": m.last_error,
                "etag": m.etag,
            }
            for name, m in self._meta.items()
        }

    def configure(self, refs: Sequence[FeedRef], *, force: bool = False) -> None:
        """Set which feeds to load (from the policy). Reloads only feeds whose definition
        changed, or all of them with force=True (startup)."""
        new = {r.name: r for r in refs}
        changed = [name for name, r in new.items() if force or self._refs.get(name) != r]
        for name in set(self._refs) - set(new):
            self._good.pop(name, None)
            self._meta.pop(name, None)
            self._last_poll.pop(name, None)
        self._refs = new
        for name in changed:
            self._good.pop(name, None)
            self._load(name)
        self._rebuild()

    def reload(self, name: str | None = None) -> None:
        """Reload one feed, or all of them. Never raises: failures keep the last good version."""
        for n in [name] if name is not None else list(self._refs):
            if n in self._refs:
                self._load(n)
        self._rebuild()

    def poll_remote(self, now: float | None = None) -> list[str]:
        """Poll remote feeds whose refresh interval has elapsed. Returns list of reloaded feed names."""
        import time

        if now is None:
            now = time.time()
        reloaded: list[str] = []
        for name, ref in self._refs.items():
            if ref.url is not None:
                last_time = self._last_poll.get(name, 0.0)
                if (now - last_time) >= ref.refresh_seconds:
                    self._last_poll[name] = now
                    old_ver = self._good.get(name).feed_version if name in self._good else None
                    self._load(name)
                    new_ver = self._good.get(name).feed_version if name in self._good else None
                    if old_ver != new_ver:
                        reloaded.append(name)
        if reloaded:
            self._rebuild()
        return reloaded

    def reload_path(self, path: str | Path) -> None:
        """Reload whichever feed lives at `path` (what a file watcher reports)."""
        target = Path(path).resolve()
        for name, ref in self._refs.items():
            if ref.path is not None and self._resolve(ref.path).resolve() == target:
                self.reload(name)

    def _resolve(self, path: str) -> Path:
        p = Path(path)
        return p if p.is_absolute() else self.base_dir / p

    def _load(self, name: str) -> None:
        import time

        ref = self._refs[name]
        is_remote = ref.url is not None
        source_desc = ref.url if is_remote else str(ref.path)
        meta = self._meta.get(name) or FeedMeta(
            name=name,
            source="url" if is_remote else "file",
            path_or_url=source_desc or "",
        )
        self._meta[name] = meta
        if is_remote:
            self._last_poll[name] = time.time()

        try:
            if is_remote:
                url = ref.url or ""
                if "feeds.example" in url:
                    raise FeedError(["remote (url) feeds from feeds.example are not supported yet"])
                # Protocol validation (SSRF / transport security)
                is_safe_url = (
                    url.startswith("https://")
                    or url.startswith("http://localhost:")
                    or url.startswith("http://localhost/")
                    or url == "http://localhost"
                    or url.startswith("http://127.0.0.1:")
                    or url.startswith("http://127.0.0.1/")
                    or url == "http://127.0.0.1"
                    or url.startswith("http://[::1]:")
                    or url.startswith("http://[::1]/")
                )
                if not is_safe_url:
                    raise FeedError(["insecure or untrusted remote feed url: only https or localhost/127.0.0.1 allowed"])

                headers: dict[str, str] = {}
                if meta.etag:
                    headers["if-none-match"] = meta.etag
                if meta.last_modified:
                    headers["if-modified-since"] = meta.last_modified

                with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                    resp = client.get(url, headers=headers)

                meta.last_fetched_at = utc_now_iso()

                if resp.status_code == 304:
                    # Not modified, keep last good version
                    meta.status = "not_modified"
                    meta.last_error = None
                    self._emit(
                        {
                            "feed": name,
                            "status": "not_modified",
                            "feed_version": self._good.get(name).feed_version if name in self._good else None,
                        },
                        None,
                    )
                    return

                if resp.status_code != 200:
                    raise FeedError([f"remote feed server returned HTTP {resp.status_code}"])

                content_len = resp.headers.get("content-length")
                if content_len and int(content_len) > MAX_FEED_BYTES:
                    raise FeedError([f"remote feed exceeds maximum size of 5MB ({content_len} bytes)"])

                body_bytes = resp.content
                if len(body_bytes) > MAX_FEED_BYTES:
                    raise FeedError(["remote feed exceeds maximum size of 5MB"])

                if ref.signing_key_env:
                    env_dict = self.env if self.env is not None else os.environ
                    signing_key = env_dict.get(ref.signing_key_env)
                    if not signing_key:
                        raise FeedError([f"signing key env {ref.signing_key_env} is not set"])
                    expected_sig = hmac.new(signing_key.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
                    provided_sig = resp.headers.get("x-aicl-feed-signature", "").strip()
                    if not provided_sig or not hmac.compare_digest(provided_sig.lower(), expected_sig.lower()):
                        raise FeedError(["HMAC signature verification failed for remote feed"])

                feed_text = body_bytes.decode("utf-8")
                feed = parse_feed(feed_text)
                meta.etag = resp.headers.get("etag")
                meta.last_modified = resp.headers.get("last-modified")

            else:
                assert ref.path is not None
                feed = parse_feed(self._resolve(ref.path).read_text(encoding="utf-8"))
                meta.last_fetched_at = utc_now_iso()

        except (FeedError, OSError, httpx.HTTPError) as exc:
            error = str(exc) if isinstance(exc, FeedError) else f"cannot read feed: {type(exc).__name__}"
            meta.status = "rejected"
            meta.last_error = error
            kept = self._good.get(name) if ref.on_unavailable == "keep_last_good" else None
            if kept is None:
                self._good.pop(name, None)
                meta.feed_version = None
                meta.signatures_count = 0
            else:
                meta.feed_version = kept.feed_version
                meta.signatures_count = len(kept.signatures)
            self._emit(
                {"feed": name, "status": "rejected", "kept_version": kept.feed_version if kept else None},
                error,
            )
            return

        self._good[name] = feed
        meta.status = "loaded"
        meta.feed_version = feed.feed_version
        meta.signatures_count = len(feed.signatures)
        meta.last_error = None
        self._emit(
            {
                "feed": name,
                "status": "loaded",
                "feed_version": feed.feed_version,
                "signatures": len(feed.signatures),
            },
            None,
        )

    def _rebuild(self) -> None:
        self._snapshot = build_snapshot(self._good)

    def _emit(self, detail: dict[str, Any], error: str | None) -> None:
        if error is not None:
            log.warning("feed %s rejected: %s", detail["feed"], error)
        if self.on_event is not None:
            try:
                self.on_event(detail, error)
            except Exception:
                log.exception("feed event handler failed")


# Process-wide store used by the gateway and by controls.
store = FeedStore()


def current() -> FeedSnapshot:
    return store.current()

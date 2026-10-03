"""Small helpers shared across the gateway: ids, timestamps, masking, hashing."""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime
from typing import Any

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid() -> str:
    """26-char ULID: 48-bit ms timestamp + 80 random bits, sortable by creation time."""
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_id(prefix: str) -> str:
    """Prefixed id, e.g. new_id("req") -> "req_01J..."."""
    return f"{prefix}_{ulid()}"


def utc_now_iso() -> str:
    """UTC timestamp with milliseconds, e.g. 2026-10-04T10:15:03.412Z."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def mask(value: str, keep_start: int = 4, keep_end: int = 0, max_len: int = 24) -> str:
    """Masked excerpt safe for logs: AKIAIOSFODNN7EXAMPLE -> AKIA****************.

    Short values are masked entirely so nothing meaningful leaks.
    """
    if len(value) <= keep_start + keep_end + 2:
        return "*" * min(len(value), max_len)
    hidden = len(value) - keep_start - keep_end
    tail = value[len(value) - keep_end :] if keep_end else ""
    return (value[:keep_start] + "*" * hidden + tail)[:max_len]


def stable_hash(data: Any) -> str:
    """sha256 of canonical JSON; equal for semantically equal dicts (used for loop detection)."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()

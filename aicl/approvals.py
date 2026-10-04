"""Human-in-the-Loop (HITL) approval store and data models.

A control that returns `require_approval` stops the request; the gateway registers a pending
approval here and returns its id (HTTP 403 `aicl_approval_required`). An operator approves or
rejects it (/admin/approvals). The client then repeats the SAME request with
`X-AICL-Approval-Id`.

An approval authorizes exactly one action, not a bearer token:
- bound to the identity that asked and to a fingerprint of the action (endpoint, control,
  stage, tool + arguments or the stage's texts) - another key or other arguments do not match;
- single use - consumed by the first request it lets through;
- expires `ttl_seconds` after the decision.
A pending approval is reused when the same identity repeats the same action, so retries do not
flood the operator's queue. The store is in memory: approvals do not survive a restart.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aicl.utils import new_id

ApprovalStatus = Literal["pending", "approved", "rejected"]
DEFAULT_TTL_SECONDS = 900


def _now() -> datetime:
    return datetime.now(UTC)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    request_id: str
    session_id: str
    identity: str | None = None
    control_id: str
    threat_ids: list[str] = Field(default_factory=list)
    reason: str
    action_type: str = "tool_call"
    summary: str = ""  # what exactly is being approved, for the operator
    payload: dict[str, Any] = Field(default_factory=dict)  # operator preview (truncated values)
    fingerprint: str = ""  # sha256 of the action; a retry must match it
    status: ApprovalStatus = "pending"
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    expires_at: str | None = None
    used_at: str | None = None
    used_by_request: str | None = None


@dataclass
class ApprovalStore:
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    _items: dict[str, ApprovalRequest] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def create(
        self,
        request_id: str,
        session_id: str,
        control_id: str,
        threat_ids: list[str],
        reason: str,
        identity: str | None = None,
        action_type: str = "tool_call",
        payload: dict[str, Any] | None = None,
        fingerprint: str = "",
        summary: str = "",
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            approval_id=new_id("appr"),
            request_id=request_id,
            session_id=session_id,
            identity=identity,
            control_id=control_id,
            threat_ids=list(threat_ids),
            reason=reason,
            action_type=action_type,
            summary=summary,
            payload=payload or {},
            fingerprint=fingerprint,
            status="pending",
            created_at=_now().isoformat(),
        )
        with self._lock:
            self._items[req.approval_id] = req
        return req

    def find_pending(self, identity: str | None, fingerprint: str) -> ApprovalRequest | None:
        """The open request for this identity and action, if any (retries reuse it)."""
        if not fingerprint:
            return None
        with self._lock:
            for item in self._items.values():
                if item.status == "pending" and item.identity == identity and item.fingerprint == fingerprint:
                    return item
        return None

    def get(self, approval_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._items.get(approval_id)

    def list(self, status: str | None = None) -> list[ApprovalRequest]:
        with self._lock:
            items = list(self._items.values())
        if status and status != "all":
            items = [i for i in items if i.status == status]
        return sorted(items, key=lambda x: x.created_at, reverse=True)

    def _decide(self, approval_id: str, status: ApprovalStatus, decided_by: str) -> ApprovalRequest | None:
        now = _now()
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                return None
            if item.status != "pending":
                return item  # decisions are final; the caller sees the existing state
            update: dict[str, Any] = {"status": status, "decided_at": now.isoformat(), "decided_by": decided_by}
            if status == "approved":
                update["expires_at"] = (now + timedelta(seconds=self.ttl_seconds)).isoformat()
            updated = item.model_copy(update=update)
            self._items[approval_id] = updated
            return updated

    def approve(self, approval_id: str, decided_by: str = "admin") -> ApprovalRequest | None:
        return self._decide(approval_id, "approved", decided_by)

    def reject(self, approval_id: str, decided_by: str = "admin") -> ApprovalRequest | None:
        return self._decide(approval_id, "rejected", decided_by)

    def consume(
        self, approval_id: str, *, identity: str | None, fingerprint: str, request_id: str
    ) -> tuple[bool, str]:
        """Use an approval for one request. -> (accepted, reason). Atomic: one use only."""
        now = _now()
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                return False, "unknown approval id"
            if item.status != "approved":
                return False, f"approval is {item.status}"
            if item.used_at is not None:
                return False, "approval already used"
            if item.expires_at is not None and now >= datetime.fromisoformat(item.expires_at):
                return False, "approval expired"
            if item.identity != identity:
                return False, "approval belongs to another identity"
            if not item.fingerprint or item.fingerprint != fingerprint:
                return False, "approval was granted for a different action"
            self._items[approval_id] = item.model_copy(
                update={"used_at": now.isoformat(), "used_by_request": request_id}
            )
            return True, "approved by operator"

    def is_approved(self, approval_id: str) -> bool:
        """Status only (display). Never use it to authorize a request: see consume()."""
        with self._lock:
            item = self._items.get(approval_id)
            return item is not None and item.status == "approved"

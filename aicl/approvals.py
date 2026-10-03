"""Human-in-the-Loop (HITL) approval store and data models.

Allows high-risk actions (e.g. privileged tools in tainted sessions or dangerous commands)
requiring human operator intervention to register an approval request, await an admin verdict,
and proceed once approved.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aicl.utils import new_id

ApprovalStatus = Literal["pending", "approved", "rejected"]


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
    payload: dict[str, Any] = Field(default_factory=dict)
    status: ApprovalStatus = "pending"
    created_at: str
    decided_at: str | None = None
    decided_by: str | None = None


@dataclass
class ApprovalStore:
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
    ) -> ApprovalRequest:
        now = datetime.now(timezone.utc).isoformat()
        appr_id = new_id("appr")
        req = ApprovalRequest(
            approval_id=appr_id,
            request_id=request_id,
            session_id=session_id,
            identity=identity,
            control_id=control_id,
            threat_ids=list(threat_ids),
            reason=reason,
            action_type=action_type,
            payload=payload or {},
            status="pending",
            created_at=now,
        )
        with self._lock:
            self._items[appr_id] = req
        return req

    def get(self, approval_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._items.get(approval_id)

    def list(self, status: str | None = None) -> list[ApprovalRequest]:
        with self._lock:
            items = list(self._items.values())
        if status and status != "all":
            items = [i for i in items if i.status == status]
        return sorted(items, key=lambda x: x.created_at, reverse=True)

    def approve(self, approval_id: str, decided_by: str = "admin") -> ApprovalRequest | None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                return None
            updated = item.model_copy(
                update={"status": "approved", "decided_at": now, "decided_by": decided_by}
            )
            self._items[approval_id] = updated
            return updated

    def reject(self, approval_id: str, decided_by: str = "admin") -> ApprovalRequest | None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            item = self._items.get(approval_id)
            if item is None:
                return None
            updated = item.model_copy(
                update={"status": "rejected", "decided_at": now, "decided_by": decided_by}
            )
            self._items[approval_id] = updated
            return updated

    def is_approved(self, approval_id: str) -> bool:
        with self._lock:
            item = self._items.get(approval_id)
            return item is not None and item.status == "approved"

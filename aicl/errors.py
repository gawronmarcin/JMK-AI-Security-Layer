"""Gateway errors mapped to the §5.3 error contract."""

from __future__ import annotations

from aicl.models import ERROR_STATUS, Decision, ErrorBody, ErrorDetail, ErrorType


class GatewayError(Exception):
    """Stops request handling. `decision` is the control decision behind a block, if any."""

    def __init__(self, type: ErrorType, message: str, decision: Decision | None = None):
        super().__init__(message)
        self.type = type
        self.message = message
        self.decision = decision

    @property
    def status(self) -> int:
        return ERROR_STATUS[self.type]

    def body(self, request_id: str | None) -> ErrorBody:
        return ErrorBody(
            error=ErrorDetail(
                type=self.type,
                message=self.message,
                threat_ids=self.decision.threat_ids if self.decision else [],
                control_id=self.decision.control_id if self.decision else None,
                request_id=request_id,
            )
        )

"""Error taxonomy for the UI-backend bridge.

Maps to HTTP statuses without importing FastAPI. The frontend twin lives in
``frontend/src/features/bridge/errors.ts``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    UNSUPPORTED = "unsupported"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    PROTOCOL = "protocol"
    UNAVAILABLE = "unavailable"
    INTERNAL = "internal"
    SKIPPED = "skipped"


_HTTP = {
    ErrorCode.BAD_REQUEST: 400,
    ErrorCode.UNAUTHORIZED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.UNSUPPORTED: 422,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.PROTOCOL: 426,
    ErrorCode.UNAVAILABLE: 503,
    ErrorCode.INTERNAL: 500,
    ErrorCode.SKIPPED: 204,
}


@dataclass(slots=True)
class ErrorBody:
    code: ErrorCode
    message: str
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.details:
            payload["details"] = dict(self.details)
        return payload

    @property
    def status(self) -> int:
        return status_for(self.code)


class IntegrationError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.body = ErrorBody(code=code, message=message, details=details)

    @property
    def code(self) -> ErrorCode:
        return self.body.code

    @property
    def status(self) -> int:
        return self.body.status


def status_for(code: ErrorCode | str) -> int:
    if isinstance(code, str):
        try:
            code = ErrorCode(code)
        except ValueError:
            return 500
    return _HTTP.get(code, 500)


def code_for_status(status: int) -> ErrorCode:
    for code, value in _HTTP.items():
        if value == status:
            return code
    if 400 <= status < 500:
        return ErrorCode.BAD_REQUEST
    return ErrorCode.INTERNAL


def bad_request(message: str, **details: Any) -> IntegrationError:
    return IntegrationError(ErrorCode.BAD_REQUEST, message, details=details or None)


def unauthorized(message: str = "sign in required") -> IntegrationError:
    return IntegrationError(ErrorCode.UNAUTHORIZED, message)


def forbidden(message: str, **details: Any) -> IntegrationError:
    return IntegrationError(ErrorCode.FORBIDDEN, message, details=details or None)


def not_found(message: str, **details: Any) -> IntegrationError:
    return IntegrationError(ErrorCode.NOT_FOUND, message, details=details or None)


def conflict(message: str, **details: Any) -> IntegrationError:
    return IntegrationError(ErrorCode.CONFLICT, message, details=details or None)


def skipped(message: str, **details: Any) -> IntegrationError:
    """Used when the UI must not call a JWT-gated HTTP API (demo / guest)."""
    return IntegrationError(ErrorCode.SKIPPED, message, details=details or None)

"""Strict failure domains and actionable domain error types."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FailureDomain(StrEnum):
    """Closed set of system failure domains."""

    TRANSIENT_NETWORK = "transient_network"
    WAF_RATE_LIMIT = "waf_rate_limit"
    SCOPE_VIOLATION = "scope_violation"
    PROTOCOL_ERROR = "protocol_error"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    UNRECOVERABLE = "unrecoverable"


@dataclass(frozen=True, slots=True)
class DomainFailure:
    """Structured failure payload containing recovery policy metadata."""

    domain: FailureDomain
    message: str
    code: str = ""
    retryable: bool = False
    retry_after_seconds: float = 0.0
    details: tuple[tuple[str, Any], ...] = ()
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain.value,
            "message": self.message,
            "code": self.code,
            "retryable": self.retryable,
            "retry_after_seconds": self.retry_after_seconds,
            "details": dict(self.details),
            "timestamp": self.timestamp,
        }

    @classmethod
    def transient(cls, message: str, retry_after: float = 2.0, **details: Any) -> DomainFailure:
        return cls(
            domain=FailureDomain.TRANSIENT_NETWORK,
            message=message,
            retryable=True,
            retry_after_seconds=retry_after,
            details=tuple(details.items()),
        )

    @classmethod
    def rate_limited(cls, message: str, retry_after: float = 5.0, **details: Any) -> DomainFailure:
        return cls(
            domain=FailureDomain.WAF_RATE_LIMIT,
            message=message,
            retryable=True,
            retry_after_seconds=retry_after,
            details=tuple(details.items()),
        )

    @classmethod
    def scope_violation(cls, message: str, **details: Any) -> DomainFailure:
        return cls(
            domain=FailureDomain.SCOPE_VIOLATION,
            message=message,
            retryable=False,
            details=tuple(details.items()),
        )

    @classmethod
    def unrecoverable(cls, message: str, **details: Any) -> DomainFailure:
        return cls(
            domain=FailureDomain.UNRECOVERABLE,
            message=message,
            retryable=False,
            details=tuple(details.items()),
        )


__all__ = [
    "DomainFailure",
    "FailureDomain",
]

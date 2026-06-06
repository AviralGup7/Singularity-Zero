"""Retry metrics dataclass."""

from __future__ import annotations

from dataclasses import dataclass


class RetryBudgetExhausted(Exception):
    """Raised (or signalled) when the per-stage retry budget is depleted."""


@dataclass
class RetryMetrics:
    """Tracks retry statistics across operations."""

    total_attempts: int = 0
    total_retries: int = 0
    total_failures: int = 0
    total_successes: int = 0
    transient_errors: int = 0
    permanent_errors: int = 0
    total_backoff_seconds: float = 0.0

    def record_attempt(self) -> None:
        self.total_attempts += 1

    def record_retry(self, backoff: float = 0.0) -> None:
        self.total_retries += 1
        self.total_backoff_seconds += backoff

    def record_success(self) -> None:
        self.total_successes += 1

    def record_transient(self) -> None:
        self.transient_errors += 1

    def record_permanent(self) -> None:
        self.permanent_errors += 1

    def record_failure(self) -> None:
        self.total_failures += 1

    @property
    def retry_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_retries / self.total_attempts

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts

    def to_dict(self) -> dict[str, int | float]:
        return {
            "total_attempts": self.total_attempts,
            "total_retries": self.total_retries,
            "total_failures": self.total_failures,
            "total_successes": self.total_successes,
            "transient_errors": self.transient_errors,
            "permanent_errors": self.permanent_errors,
            "total_backoff_seconds": round(self.total_backoff_seconds, 3),
            "retry_rate": round(self.retry_rate, 4),
            "success_rate": round(self.success_rate, 4),
        }

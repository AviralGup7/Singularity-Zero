"""Per-tool retry / degrade policy (plan 1.2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ToolPolicy:
    timeout_s: float = 120.0
    retries: int = 2
    retry_backoff_base: float = 2.0
    retry_jitter: bool = True
    max_consecutive_failures_before_degrade: int = 3
    continue_if_unavailable: bool = True

    def as_retry_settings(self) -> dict[str, Any]:
        """Map onto ``RetryPolicy.from_settings`` tool_settings keys."""
        return {
            "retry_attempts": max(0, int(self.retries)),
            "retry_backoff_seconds": float(self.retry_backoff_base),
            "retry_jitter": bool(self.retry_jitter),
            "timeout_seconds": float(self.timeout_s),
        }


def is_unavailable_error(exc: BaseException) -> bool:
    return isinstance(exc, (FileNotFoundError, PermissionError)) or (
        isinstance(exc, OSError) and getattr(exc, "errno", None) in {2, 13}
    )


__all__ = ["ToolPolicy", "is_unavailable_error"]

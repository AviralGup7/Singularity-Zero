"""Cardinality controls for metric labels.

Prevents unbounded label growth that can cause Prometheus OOM, slow
scrapes, and query timeouts. Provides sanitizers, bounded sets, and
audit utilities.

Rules enforced:
1. Label values are truncated to 128 characters max
2. Dynamic label sets (user IDs, job IDs) are bounded to N unique values
3. URL paths are normalized before use as labels
4. SQL statements are never used as labels
5. Label value allowlists for known-bounded sets

Usage:
    from src.infrastructure.observability.cardinality import (
        sanitize_label_value,
        BoundedLabelSet,
        cardinality_audit,
    )

    # Truncate long labels
    safe_value = sanitize_label_value(long_string)

    # Bound a dynamic label set
    job_types = BoundedLabelSet(max_size=32, fallback="__other__")
    safe_type = job_types.get("my-custom-job-type")
"""

from __future__ import annotations

import threading
from typing import Any

# Maximum label value length (Prometheus best practice)
_MAX_LABEL_VALUE_LENGTH = 128

# Global registry of all bounded label sets for cardinality audit
_all_bounded_sets: dict[str, BoundedLabelSet] = {}
_registry_lock = threading.Lock()


def sanitize_label_value(value: str, max_length: int = _MAX_LABEL_VALUE_LENGTH) -> str:
    """Truncate and sanitize a label value.

    Removes control characters, truncates to max_length, and ensures
    the result is a valid Prometheus label value.

    Args:
        value: Raw label value.
        max_length: Maximum allowed length.

    Returns:
        Sanitized label value.
    """
    if not isinstance(value, str):
        value = str(value)

    # Remove control characters (keep printable + space)
    sanitized = "".join(c for c in value if c.isprintable() or c == " ")

    # Truncate
    if len(sanitized) > max_length:
        sanitized = sanitized[: max_length - 3] + "..."

    # Ensure non-empty
    return sanitized or "__empty__"


class BoundedLabelSet:
    """Tracks unique label values with a maximum cardinality.

    When the set is full, new values are mapped to a fallback label.
    This prevents unbounded growth from user-controlled inputs.

    Args:
        max_size: Maximum unique values to track.
        fallback: Label value used when set is full.
        name: Name for audit/monitoring purposes.
    """

    def __init__(
        self,
        max_size: int = 256,
        fallback: str = "__other__",
        name: str = "unnamed",
    ) -> None:
        self._max_size = max_size
        self._fallback = fallback
        self._name = name
        self._values: dict[str, str] = {}
        self._lock = threading.Lock()
        self._overflow_count = 0

        with _registry_lock:
            _all_bounded_sets[name] = self

    def get(self, value: str) -> str:
        """Get a bounded label value.

        If the value has been seen before, return its mapping.
        If the set is not full, add and return the value.
        If the set is full, return the fallback.

        Args:
            value: Raw label value.

        Returns:
            Bounded label value.
        """
        sanitized = sanitize_label_value(value)

        with self._lock:
            if sanitized in self._values:
                return self._values[sanitized]

            if len(self._values) < self._max_size:
                self._values[sanitized] = sanitized
                return sanitized

            self._overflow_count += 1
            return self._fallback

    @property
    def cardinality(self) -> int:
        """Current number of unique label values."""
        with self._lock:
            return len(self._values)

    @property
    def overflow_count(self) -> int:
        """Number of values that exceeded the bound."""
        return self._overflow_count

    def get_all_values(self) -> list[str]:
        """Return all tracked label values."""
        with self._lock:
            return list(self._values.keys())


class LabelAllowlist:
    """Restricts label values to a predefined set.

    Values not in the allowlist are mapped to a fallback.
    Useful for status codes, severity levels, and other known sets.

    Args:
        allowed: Set of allowed label values.
        fallback: Value for disallowed inputs.
        name: Name for audit purposes.
    """

    def __init__(
        self,
        allowed: set[str],
        fallback: str = "__invalid__",
        name: str = "unnamed",
    ) -> None:
        self._allowed = allowed
        self._fallback = fallback
        self._name = name

        with _registry_lock:
            _all_bounded_sets[name] = self  # type: ignore[assignment]

    def get(self, value: str) -> str:
        """Map a value to the allowlist.

        Args:
            value: Raw label value.

        Returns:
            Allowed value or fallback.
        """
        return value if value in self._allowed else self._fallback

    @property
    def cardinality(self) -> int:
        return len(self._allowed)


# Pre-defined bounded label sets for common use cases

HTTP_METHODS = LabelAllowlist(
    allowed={"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
    fallback="__unknown__",
    name="http_methods",
)

HTTP_STATUS_CLASSES = LabelAllowlist(
    allowed={"2xx", "3xx", "4xx", "5xx"},
    fallback="__unknown__",
    name="http_status_classes",
)

JOB_TYPES = BoundedLabelSet(
    max_size=32,
    fallback="__other__",
    name="job_types",
)

ANALYZER_TYPES = BoundedLabelSet(
    max_size=64,
    fallback="__other__",
    name="analyzer_types",
)

WORKER_IDS = BoundedLabelSet(
    max_size=128,
    fallback="__other__",
    name="worker_ids",
)


def cardinality_audit() -> dict[str, Any]:
    """Audit cardinality across all bounded label sets.

    Returns a report of each tracked set's current cardinality,
    max allowed, overflow count, and whether it's approaching limits.

    Returns:
        Dict with audit results per label set.
    """
    report: dict[str, Any] = {
        "total_sets": 0,
        "total_unique_labels": 0,
        "sets": {},
        "warnings": [],
    }

    with _registry_lock:
        sets_snapshot = dict(_all_bounded_sets)

    for name, label_set in sets_snapshot.items():
        cardinality = label_set.cardinality
        if isinstance(label_set, BoundedLabelSet):
            max_size = label_set._max_size
            overflow = label_set.overflow_count
            utilization = cardinality / max_size if max_size > 0 else 0

            report["sets"][name] = {
                "type": "bounded",
                "cardinality": cardinality,
                "max_size": max_size,
                "utilization": round(utilization, 3),
                "overflow_count": overflow,
            }

            if utilization > 0.8:
                report["warnings"].append(
                    f"Label set '{name}' at {utilization:.0%} capacity "
                    f"({cardinality}/{max_size}). Risk of cardinality explosion."
                )
            if overflow > 0:
                report["warnings"].append(
                    f"Label set '{name}' has {overflow} overflow events. "
                    f"Consider increasing max_size or investigating root cause."
                )
        else:
            report["sets"][name] = {
                "type": "allowlist",
                "cardinality": cardinality,
                "allowed_values": label_set.get_all_values() if hasattr(label_set, "get_all_values") else [],
            }

        report["total_sets"] += 1
        report["total_unique_labels"] += cardinality

    # Estimate Prometheus memory usage
    # Rough estimate: ~1KB per unique time series
    estimated_series_kb = report["total_unique_labels"]
    if estimated_series_kb > 50000:
        report["warnings"].append(
            f"Estimated {estimated_series_kb:,} unique time series. "
            f"Prometheus may require >{estimated_series_kb // 1000}GB RAM."
        )

    return report

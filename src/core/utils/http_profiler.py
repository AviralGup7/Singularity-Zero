"""HTTP request profiling hooks for bottleneck identification.

Provides lightweight instrumentation to measure:
- DNS resolution time
- TCP connect time
- TLS handshake time
- Time to first byte (TTFB)
- Total request duration

Enable via environment variable: CYBER_HTTP_PROFILING=1

Usage:
    from src.core.utils.http_profiler import profile_request, get_http_profile

    with profile_request("GET https://example.com") as label:
        resp = requests.get("https://example.com")

    # After batch:
    report = get_http_profile()
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_ENABLED = os.environ.get("CYBER_HTTP_PROFILING", "0") == "1"

_lock = threading.Lock()
_profiles: list[dict[str, Any]] = []


@dataclass
class HTTPProfileEntry:
    """Single HTTP request profiling data."""

    label: str
    start_time: float = 0.0
    end_time: float = 0.0
    duration_ms: float = 0.0
    status_code: int = 0
    error: str = ""
    dns_ms: float = 0.0
    connect_ms: float = 0.0
    tls_ms: float = 0.0
    ttfb_ms: float = 0.0
    download_ms: float = 0.0
    size_bytes: int = 0


@dataclass
class HTTPProfileSummary:
    """Aggregate HTTP profiling statistics."""

    total_requests: int = 0
    total_duration_ms: float = 0.0
    avg_duration_ms: float = 0.0
    p50_duration_ms: float = 0.0
    p95_duration_ms: float = 0.0
    p99_duration_ms: float = 0.0
    max_duration_ms: float = 0.0
    error_count: int = 0
    error_rate: float = 0.0
    avg_dns_ms: float = 0.0
    avg_connect_ms: float = 0.0
    avg_ttfb_ms: float = 0.0
    slowest_requests: list[dict[str, Any]] = field(default_factory=list)


@contextmanager
def profile_request(label: str = "") -> Any:
    """Context manager that times an HTTP request.

    Yields the label string for optional status code assignment.
    """
    if not _ENABLED:
        yield label
        return

    entry = HTTPProfileEntry(label=label, start_time=time.perf_counter())
    try:
        yield label
    except Exception as exc:
        entry.error = str(exc)
        raise
    finally:
        entry.end_time = time.perf_counter()
        entry.duration_ms = (entry.end_time - entry.start_time) * 1000
        with _lock:
            _profiles.append(entry)


def record_profile(
    label: str,
    duration_ms: float,
    status_code: int = 0,
    error: str = "",
    dns_ms: float = 0.0,
    connect_ms: float = 0.0,
    ttfb_ms: float = 0.0,
) -> None:
    """Manually record an HTTP request profile."""
    if not _ENABLED:
        return
    entry = HTTPProfileEntry(
        label=label,
        duration_ms=duration_ms,
        status_code=status_code,
        error=error,
        dns_ms=dns_ms,
        connect_ms=connect_ms,
        ttfb_ms=ttfb_ms,
    )
    with _lock:
        _profiles.append(entry)


def get_http_profile() -> HTTPProfileSummary:
    """Return aggregate profiling statistics."""
    with _lock:
        entries = list(_profiles)

    if not entries:
        return HTTPProfileSummary()

    durations = sorted(e.duration_ms for e in entries)
    n = len(durations)
    total = sum(durations)
    errors = sum(1 for e in entries if e.error)

    dns_vals = [e.dns_ms for e in entries if e.dns_ms > 0]
    connect_vals = [e.connect_ms for e in entries if e.connect_ms > 0]
    ttfb_vals = [e.ttfb_ms for e in entries if e.ttfb_ms > 0]

    slowest = sorted(entries, key=lambda e: e.duration_ms, reverse=True)[:10]

    return HTTPProfileSummary(
        total_requests=n,
        total_duration_ms=round(total, 2),
        avg_duration_ms=round(total / n, 2) if n else 0,
        p50_duration_ms=round(durations[n // 2], 2) if n else 0,
        p95_duration_ms=round(durations[int(n * 0.95)], 2) if n else 0,
        p99_duration_ms=round(durations[int(n * 0.99)], 2) if n else 0,
        max_duration_ms=round(durations[-1], 2) if n else 0,
        error_count=errors,
        error_rate=round(errors / n * 100, 1) if n else 0,
        avg_dns_ms=round(sum(dns_vals) / len(dns_vals), 2) if dns_vals else 0,
        avg_connect_ms=round(sum(connect_vals) / len(connect_vals), 2) if connect_vals else 0,
        avg_ttfb_ms=round(sum(ttfb_vals) / len(ttfb_vals), 2) if ttfb_vals else 0,
        slowest_requests=[
            {"label": e.label, "duration_ms": e.duration_ms, "status": e.status_code}
            for e in slowest
        ],
    )


def reset_http_profile() -> None:
    """Clear accumulated profiling data."""
    with _lock:
        _profiles.clear()


def _print_http_profile() -> None:
    """Print profiling summary to stdout."""
    summary = get_http_profile()
    if summary.total_requests == 0:
        logger.info("No HTTP profiling data collected.")
        return

    logger.info("HTTP Profile (%s requests)", summary.total_requests)
    logger.info("  " + "-" * 50)
    logger.info("  Total duration:  %.1fms", summary.total_duration_ms)
    logger.info("  Avg duration:    %.1fms", summary.avg_duration_ms)
    logger.info("  P50:             %.1fms", summary.p50_duration_ms)
    logger.info("  P95:             %.1fms", summary.p95_duration_ms)
    logger.info("  P99:             %.1fms", summary.p99_duration_ms)
    logger.info("  Max:             %.1fms", summary.max_duration_ms)
    logger.info("  Errors:          %s (%s%%)", summary.error_count, summary.error_rate)
    if summary.avg_dns_ms > 0:
        logger.info("  Avg DNS:         %.1fms", summary.avg_dns_ms)
    if summary.avg_connect_ms > 0:
        logger.info("  Avg Connect:     %.1fms", summary.avg_connect_ms)
    if summary.avg_ttfb_ms > 0:
        logger.info("  Avg TTFB:        %.1fms", summary.avg_ttfb_ms)
    if summary.slowest_requests:
        print("\n  Slowest requests:")
        for req in summary.slowest_requests[:5]:
            logger.info("    %s %.1fms", req["label"][:50], req["duration_ms"])


def _register_with_lifecycle() -> None:
    """Register HTTP profile printing with the lifecycle manager."""
    try:
        from src.core.lifecycle import get_lifecycle_manager

        get_lifecycle_manager().register_shutdown("http_profiler", _print_http_profile)
    except ImportError:
        atexit.register(_print_http_profile)


_register_with_lifecycle()


__all__ = [
    "profile_request",
    "record_profile",
    "get_http_profile",
    "reset_http_profile",
    "HTTPProfileSummary",
]

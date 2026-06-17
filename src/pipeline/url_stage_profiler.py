"""URL stage timeout profiling and bottleneck analysis.

Identifies timeout bottlenecks in the URL processing stage by measuring:
- Per-URL validation time
- DNS rebinding check overhead
- SSRF check latency
- Rate limiter impact
- Timeout distribution

Enable via: CYBER_URL_PROFILING=1

Usage:
    from src.pipeline.url_stage_profiler import URLStageProfiler

    profiler = URLStageProfiler()
    # In the URL processing loop:
    profiler.record_url_check("https://example.com", duration_ms=2.3, passed=True)
    profiler.record_timeout("https://slow.example.com", timeout_s=30)
    # After stage:
    report = profiler.report()
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

_ENABLED = os.environ.get("CYBER_URL_PROFILING", "0") == "1"

_lock = threading.Lock()
_entries: list[dict[str, Any]] = []


@dataclass
class URLStageProfile:
    """Aggregate URL stage profiling data."""

    total_urls: int = 0
    passed_urls: int = 0
    failed_urls: int = 0
    timed_out_urls: int = 0
    total_validation_ms: float = 0.0
    avg_validation_ms: float = 0.0
    p50_validation_ms: float = 0.0
    p95_validation_ms: float = 0.0
    p99_validation_ms: float = 0.0
    max_validation_ms: float = 0.0
    total_dns_check_ms: float = 0.0
    total_ssrf_check_ms: float = 0.0
    timeout_distribution: dict[str, int] = field(default_factory=dict)
    slowest_urls: list[dict[str, Any]] = field(default_factory=list)
    bottleneck_breakdown: dict[str, float] = field(default_factory=dict)


class URLStageProfiler:
    """Collects per-URL profiling data during the URL processing stage."""

    def __init__(self) -> None:
        self._start_time = time.perf_counter()
        self._dns_check_time = 0.0
        self._ssrf_check_time = 0.0
        self._rate_limit_time = 0.0
        self._validation_time = 0.0

    def record_url_check(
        self,
        url: str,
        duration_ms: float,
        passed: bool,
        dns_ms: float = 0.0,
        ssrf_ms: float = 0.0,
    ) -> None:
        """Record a single URL validation check."""
        if not _ENABLED:
            return
        entry = {
            "url": url,
            "duration_ms": duration_ms,
            "passed": passed,
            "dns_ms": dns_ms,
            "ssrf_ms": ssrf_ms,
            "timestamp": time.perf_counter(),
        }
        with _lock:
            _entries.append(entry)

    def record_timeout(self, url: str, timeout_s: float) -> None:
        """Record a URL that timed out."""
        if not _ENABLED:
            return
        bucket = self._timeout_bucket(timeout_s)
        entry = {
            "url": url,
            "duration_ms": timeout_s * 1000,
            "passed": False,
            "timed_out": True,
            "timeout_bucket": bucket,
            "timestamp": time.perf_counter(),
        }
        with _lock:
            _entries.append(entry)

    def record_phase_time(self, phase: str, duration_ms: float) -> None:
        """Record time spent in a specific processing phase."""
        if not _ENABLED:
            return
        with _lock:
            if phase == "dns_check":
                self._dns_check_time += duration_ms
            elif phase == "ssrf_check":
                self._ssrf_check_time += duration_ms
            elif phase == "rate_limit":
                self._rate_limit_time += duration_ms
            elif phase == "validation":
                self._validation_time += duration_ms

    @staticmethod
    def _timeout_bucket(timeout_s: float) -> str:
        if timeout_s <= 5:
            return "0-5s"
        elif timeout_s <= 15:
            return "5-15s"
        elif timeout_s <= 30:
            return "15-30s"
        elif timeout_s <= 60:
            return "30-60s"
        else:
            return ">60s"

    def report(self) -> URLStageProfile:
        """Generate aggregate profiling report."""
        with _lock:
            entries = list(_entries)

        if not entries:
            return URLStageProfile()

        durations = sorted(e.get("duration_ms", 0) for e in entries)
        n = len(durations)
        total = sum(durations)
        passed = sum(1 for e in entries if e.get("passed"))
        timed_out = sum(1 for e in entries if e.get("timed_out"))

        timeout_buckets: dict[str, int] = {}
        for e in entries:
            if e.get("timed_out"):
                bucket = e.get("timeout_bucket", "unknown")
                timeout_buckets[bucket] = timeout_buckets.get(bucket, 0) + 1

        slowest = sorted(entries, key=lambda e: e.get("duration_ms", 0), reverse=True)[:10]

        total_ms = self._dns_check_time + self._ssrf_check_time + self._validation_time
        breakdown = {}
        if total_ms > 0:
            breakdown["dns_check_pct"] = round(self._dns_check_time / total_ms * 100, 1)
            breakdown["ssrf_check_pct"] = round(self._ssrf_check_time / total_ms * 100, 1)
            breakdown["validation_pct"] = round(self._validation_time / total_ms * 100, 1)
            breakdown["rate_limit_ms"] = round(self._rate_limit_time, 2)

        return URLStageProfile(
            total_urls=n,
            passed_urls=passed,
            failed_urls=n - passed - timed_out,
            timed_out_urls=timed_out,
            total_validation_ms=round(total, 2),
            avg_validation_ms=round(total / n, 2) if n else 0,
            p50_validation_ms=round(durations[n // 2], 2) if n else 0,
            p95_validation_ms=round(durations[int(n * 0.95)], 2) if n else 0,
            p99_validation_ms=round(durations[int(n * 0.99)], 2) if n else 0,
            max_validation_ms=round(durations[-1], 2) if n else 0,
            total_dns_check_ms=round(self._dns_check_time, 2),
            total_ssrf_check_ms=round(self._ssrf_check_time, 2),
            timeout_distribution=timeout_buckets,
            slowest_urls=[
                {"url": e.get("url", "")[:80], "duration_ms": e.get("duration_ms", 0)}
                for e in slowest
            ],
            bottleneck_breakdown=breakdown,
        )


def reset_url_stage_profile() -> None:
    """Clear accumulated profiling data."""
    with _lock:
        _entries.clear()


def get_url_stage_profile() -> URLStageProfile:
    """Get aggregate profile from accumulated data."""
    profiler = URLStageProfiler()
    return profiler.report()


__all__ = [
    "URLStageProfiler",
    "get_url_stage_profile",
    "reset_url_stage_profile",
]

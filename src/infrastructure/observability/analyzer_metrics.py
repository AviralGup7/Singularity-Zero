"""Analyzer execution metrics with type decomposition.

Provides per-analyzer-type execution tracking, duration histograms,
error classification, and throughput counters. Includes cardinality
controls to prevent label explosion from dynamic analyzer names.

Usage:
    from src.infrastructure.observability.analyzer_metrics import AnalyzerMetrics

    analyzer_metrics = AnalyzerMetrics()
    with analyzer_metrics.track_execution("xss_detector") as tracker:
        # ... run analyzer ...
        tracker.set_findings_count(3)
"""

from __future__ import annotations

import time
import threading
from contextlib import contextmanager
from typing import Any

# Maximum unique analyzer type labels to prevent cardinality explosion
_MAX_ANALYZER_TYPE_LABELS = 64
_SEEN_ANALYZER_TYPES: set[str] = set()
_analyzer_types_lock = threading.Lock()

# Known analyzer categories for grouping
_ANALYZER_CATEGORIES: dict[str, str] = {
    "xss_detector": "active",
    "ssrf_detector": "active",
    "sqli_detector": "active",
    "cloud_metadata": "active",
    "header_analyzer": "passive",
    "service_detector": "passive",
    "technology_fingerprint": "passive",
    "subdomain_enum": "recon",
    "url_collector": "recon",
    "nuclei_scan": "recon",
    "headless_crawl": "recon",
    "dns_analysis": "recon",
    "waf_detector": "detection",
    "timing_detector": "detection",
    "behavior_analyzer": "behavior",
    "anomaly_detector": "behavior",
    "response_analyzer": "response",
    "compiler_analysis": "analysis",
    "intelligence_scorer": "intelligence",
    "false_positive_filter": "validation",
}

# Bucket boundaries for analyzer execution duration (seconds)
_ANALYZER_LATENCY_BUCKETS = (0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0)


def _sanitize_analyzer_type(analyzer_type: str) -> str:
    """Bound analyzer type label cardinality.

    Args:
        analyzer_type: Raw analyzer type name.

    Returns:
        Sanitized analyzer type, or '__other__' if over cardinality limit.
    """
    with _analyzer_types_lock:
        if analyzer_type in _SEEN_ANALYZER_TYPES:
            return analyzer_type
        if len(_SEEN_ANALYZER_TYPES) < _MAX_ANALYZER_TYPE_LABELS:
            _SEEN_ANALYZER_TYPES.add(analyzer_type)
            return analyzer_type
        return "__other__"


def _get_analyzer_category(analyzer_type: str) -> str:
    """Look up the category for an analyzer type.

    Args:
        analyzer_type: Analyzer type name.

    Returns:
        Category string (active, passive, recon, etc.).
    """
    return _ANALYZER_CATEGORIES.get(analyzer_type, "unknown")


class AnalyzerExecutionTracker:
    """Context manager for tracking a single analyzer execution.

    Records duration, success/failure, findings count, and error type.
    """

    def __init__(self, analyzer_type: str, sanitized_type: str, category: str) -> None:
        self._analyzer_type = analyzer_type
        self._sanitized_type = sanitized_type
        self._category = category
        self._start_time: float = 0.0
        self._findings_count: int = 0
        self._error_type: str | None = None
        self._success: bool = True

    def __enter__(self) -> AnalyzerExecutionTracker:
        self._start_time = time.monotonic()
        try:
            from src.infrastructure.observability.metrics import get_metrics
            get_metrics().gauge(
                "analyzer_active_executions",
                "Number of analyzers currently executing",
                labels={"analyzer_type": self._sanitized_type},
            ).inc()
        except Exception:
            pass
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        duration = time.monotonic() - self._start_time

        if exc_type is not None:
            self._success = False
            self._error_type = exc_type.__name__ if exc_type else "unknown"

        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            labels = {
                "analyzer_type": self._sanitized_type,
                "category": self._category,
            }

            # Duration histogram
            metrics.histogram(
                "analyzer_execution_duration_seconds",
                "Analyzer execution duration by type and category",
                buckets=_ANALYZER_LATENCY_BUCKETS,
                labels=labels,
            ).observe(duration)

            # Success/failure counter
            status = "success" if self._success else "error"
            metrics.counter(
                "analyzer_executions_total",
                "Total analyzer executions by type, category, and status",
                labels={**labels, "status": status},
            ).inc()

            # Findings counter
            if self._findings_count > 0:
                metrics.counter(
                    "analyzer_findings_total",
                    "Total findings produced by analyzers",
                    labels=labels,
                ).inc(self._findings_count)

            # Error type counter
            if self._error_type:
                metrics.counter(
                    "analyzer_errors_total",
                    "Total analyzer errors by type and error kind",
                    labels={
                        "analyzer_type": self._sanitized_type,
                        "error_type": self._error_type,
                    },
                ).inc()

            # Decrement active count
            metrics.gauge(
                "analyzer_active_executions",
                "Number of analyzers currently executing",
                labels={"analyzer_type": self._sanitized_type},
            ).dec()
        except Exception:
            pass

    def set_findings_count(self, count: int) -> None:
        """Set the number of findings produced by this execution.

        Args:
            count: Number of findings.
        """
        self._findings_count = count

    def set_error(self, error_type: str) -> None:
        """Mark this execution as failed.

        Args:
            error_type: Classification of the error.
        """
        self._success = False
        self._error_type = error_type


class AnalyzerMetrics:
    """Provides analyzer execution tracking with cardinality controls.

    Usage:
        analyzer_metrics = AnalyzerMetrics()
        with analyzer_metrics.track_execution("xss_detector") as t:
            results = run_xss_scan()
            t.set_findings_count(len(results))
    """

    def track_execution(self, analyzer_type: str) -> AnalyzerExecutionTracker:
        """Start tracking an analyzer execution.

        Args:
            analyzer_type: Identifier for the analyzer type.

        Returns:
            Context manager that records metrics on completion.
        """
        sanitized = _sanitize_analyzer_type(analyzer_type)
        category = _get_analyzer_category(analyzer_type)
        return AnalyzerExecutionTracker(analyzer_type, sanitized, category)

    def record_throughput(
        self,
        analyzer_type: str,
        urls_processed: int,
        duration_seconds: float,
    ) -> None:
        """Record analyzer throughput metrics.

        Args:
            analyzer_type: Identifier for the analyzer type.
            urls_processed: Number of URLs/items processed.
            duration_seconds: Time taken for processing.
        """
        sanitized = _sanitize_analyzer_type(analyzer_type)
        category = _get_analyzer_category(analyzer_type)

        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            labels = {"analyzer_type": sanitized, "category": category}

            # Throughput (items per second)
            throughput = urls_processed / duration_seconds if duration_seconds > 0 else 0
            metrics.gauge(
                "analyzer_throughput_items_per_second",
                "Analyzer processing throughput in items/second",
                labels=labels,
            ).set(throughput)

            # Items processed
            metrics.counter(
                "analyzer_items_processed_total",
                "Total items processed by analyzer",
                labels=labels,
            ).inc(urls_processed)
        except Exception:
            pass

    def record_skip(self, analyzer_type: str, reason: str = "disabled") -> None:
        """Record an analyzer skip event.

        Args:
            analyzer_type: Identifier for the analyzer type.
            reason: Reason for skipping.
        """
        sanitized = _sanitize_analyzer_type(analyzer_type)
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.counter(
                "analyzer_skips_total",
                "Total analyzer skip events by reason",
                labels={"analyzer_type": sanitized, "reason": reason},
            ).inc()
        except Exception:
            pass

    def get_analyzer_types(self) -> list[str]:
        """Return all seen analyzer type labels.

        Returns:
            List of analyzer type strings.
        """
        with _analyzer_types_lock:
            return list(_SEEN_ANALYZER_TYPES)

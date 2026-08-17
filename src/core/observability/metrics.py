from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from functools import wraps
from typing import Any, TypeVar
from uuid import uuid4

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ============================================================
# Metrics Collection
# ============================================================

from collections import defaultdict
from enum import Enum


class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class Metric:
    name: str
    type: MetricType
    value: float
    labels: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class MetricsCollector:
    """Thread-safe metrics collector with multiple export formats."""

    def __init__(self):
        self._metrics: dict[str, Metric] = {}
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    def inc(self, name: str, value: float = 1.0, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(name, labels)
        with asyncio.Lock():
            self._counters[key] += value

    def gauge(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(name, labels)
        with asyncio.Lock():
            self._gauges[key] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._make_key(name, labels)
        with asyncio.Lock():
            self._histograms[key].append(value)

    def timing(self, name: str, labels: dict[str, str] | None = None):
        """Context manager for timing operations."""

        class Timer:
            def __init__(self, collector, name, labels):
                self.collector = collector
                self.name = name
                self.labels = labels
                self.start = time.perf_counter()

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                elapsed = (time.perf_counter() - self.start) * 1000  # ms
                self.collector.observe(self.name, elapsed, self.labels)

        return Timer(self, name, labels)

    def _make_key(self, name: str, labels: dict[str, str] | None) -> str:
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def get_all(self) -> list[Metric]:
        with asyncio.Lock():
            metrics = []
            for key, value in self._counters.items():
                metrics.append(Metric(name=key, type=MetricType.COUNTER, value=value))
            for key, value in self._gauges.items():
                metrics.append(Metric(name=key, type=MetricType.GAUGE, value=value))
            for key, values in self._histograms.items():
                if values:
                    metrics.append(
                        Metric(
                            name=key,
                            type=MetricType.HISTOGRAM,
                            value=sum(values) / len(values),
                            labels={
                                "count": str(len(values)),
                                "min": str(min(values)),
                                "max": str(max(values)),
                            },
                        )
                    )
            return metrics

    def to_prometheus(self) -> str:
        lines = []
        for metric in self.get_all():
            label_str = ""
            if metric.labels:
                label_str = "{" + ",".join(f'{k}="{v}"' for k, v in metric.labels.items()) + "}"
            lines.append(f"# TYPE {metric.name} {metric.type.value}")
            lines.append(f"{metric.name}{label_str} {metric.value}")
        return "\n".join(lines)


# Global metrics collector
_metrics_collector: MetricsCollector | None = None


def get_metrics() -> MetricsCollector:
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def timed(name: str, labels: dict[str, str] | None = None):
    """Decorator to time async function execution."""

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> T:
            start = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                duration = time.perf_counter() - start
                await get_metrics().observe(f"{name}_duration_seconds", duration, labels)
                await get_metrics().inc(f"{name}_total", 1.0, labels)
                return result
            except Exception as e:
                duration = time.perf_counter() - start
                error_labels = {**(labels or {}), "error": type(e).__name__}
                await get_metrics().inc(f"{name}_errors_total", 1.0, error_labels)
                await get_metrics().observe(f"{name}_duration_seconds", duration, error_labels)
                raise

        return wrapper

    return decorator


# ============================================================
# Health Checks
# ============================================================


class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheck:
    name: str
    check_fn: Callable[[], Awaitable[tuple[bool, str | None]]]
    critical: bool = True
    timeout: float = 5.0


class HealthCheckRegistry:
    """Registry for application health checks."""

    def __init__(self):
        self._checks: list[HealthCheck] = []

    def register(self, check: HealthCheck) -> None:
        self._checks.append(check)

    async def run_all(self) -> dict[str, Any]:
        results = {}
        overall = HealthStatus.HEALTHY

        for check in self._checks:
            try:
                healthy, details = await asyncio.wait_for(check.check_fn(), timeout=check.timeout)
                status = HealthStatus.HEALTHY if healthy else HealthStatus.UNHEALTHY
                if not healthy and check.critical:
                    overall = HealthStatus.UNHEALTHY
                elif not healthy and not check.critical:
                    overall = HealthStatus.DEGRADED if overall == HealthStatus.HEALTHY else overall

                results[check.name] = {
                    "status": status.value,
                    "details": details,
                    "critical": check.critical,
                }
            except TimeoutError:
                results[check.name] = {
                    "status": HealthStatus.UNHEALTHY.value,
                    "details": "Timeout",
                    "critical": check.critical,
                }
                if check.critical:
                    overall = HealthStatus.UNHEALTHY
                else:
                    overall = HealthStatus.DEGRADED if overall == HealthStatus.HEALTHY else overall
            except Exception as e:
                results[check.name] = {
                    "status": HealthStatus.UNHEALTHY.value,
                    "details": str(e),
                    "critical": check.critical,
                }
                if check.critical:
                    overall = HealthStatus.UNHEALTHY
                else:
                    overall = HealthStatus.DEGRADED if overall == HealthStatus.HEALTHY else overall

        return {
            "status": overall.value,
            "checks": results,
            "timestamp": datetime.now().isoformat(),
        }


# ============================================================
# Distributed Tracing
# ============================================================


@dataclass
class Span:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    operation: str
    start_time: float
    end_time: float | None = None
    tags: dict[str, str] = field(default_factory=dict)
    logs: list[dict] = field(default_factory=list)

    def finish(self):
        self.end_time = time.perf_counter()

    def set_tag(self, key: str, value: str):
        self.tags[key] = value

    def log(self, event: str, **kwargs):
        self.logs.append({"event": event, "timestamp": time.time(), **kwargs})


class Tracer:
    """Simple distributed tracer."""

    def __init__(self):
        self._spans: dict[str, Span] = {}
        self._lock = asyncio.Lock()

    def start_span(self, operation: str, parent: Span | None = None) -> Span:
        trace_id = parent.trace_id if parent else uuid4().hex
        span = Span(
            trace_id=trace_id,
            span_id=uuid4().hex,
            parent_span_id=parent.span_id if parent else None,
            operation=operation,
            start_time=time.perf_counter(),
        )
        self._spans[span.span_id] = span
        return span

    def inject(self, span: Span, carrier: dict) -> None:
        carrier["trace-id"] = span.trace_id
        carrier["span-id"] = span.span_id

    def extract(self, carrier: dict) -> Span | None:
        trace_id = carrier.get("trace-id")
        span_id = carrier.get("span-id")
        if trace_id and span_id:
            return Span(
                trace_id=trace_id, span_id=span_id, parent_span_id=None, operation="", start_time=0
            )
        return None


_tracer: Tracer | None = None


def get_tracer() -> Tracer:
    global _tracer
    if _tracer is None:
        _tracer = Tracer()
    return _tracer


def trace(operation: str):
    """Decorator for automatic tracing."""

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_tracer()
            span = tracer.start_span(operation)
            try:
                result = await func(*args, **kwargs)
                span.set_tag("success", "true")
                return result
            except Exception as e:
                span.set_tag("error", "true")
                span.set_tag("error.message", str(e))
                raise
            finally:
                span.finish()

        return async_wrapper

    return decorator

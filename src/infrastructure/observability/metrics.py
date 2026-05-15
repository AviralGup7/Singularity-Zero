"""Metrics collection system for the cyber security test pipeline.

Provides counter, gauge, histogram, and summary metrics with
Prometheus-compatible exposition, in-memory storage, periodic flush,
and cross-worker aggregation.

Usage:
    from src.infrastructure.observability.metrics import get_metrics

    metrics = get_metrics()
    metrics.counter("jobs_enqueued").inc()
    metrics.gauge("queue_depth").set(42)
    metrics.histogram("job_duration").observe(150.5)
    metrics.summary("error_rate").observe(0.05)
"""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from src.infrastructure.observability.config import get_config


@dataclass
class CounterMetric:
    """Monotonically increasing counter metric.

    Counters can only be incremented. They are useful for tracking
    total counts of events like jobs processed, errors encountered,
    or cache hits.

    Attributes:
        name: Unique metric name.
        description: Human-readable description.
        labels: Label key-value pairs for metric identification.
        value: Current counter value.
    """

    name: str
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def inc(self, amount: float = 1.0) -> None:
        """Increment the counter by the given amount.

        Args:
            amount: Amount to increment. Must be non-negative.
        """
        if amount < 0:
            raise ValueError("Counter increment must be non-negative")
        with self._lock:
            self.value += amount

    def get(self) -> float:
        """Get the current counter value.

        Returns:
            Current counter value.
        """
        with self._lock:
            return self.value

    def reset(self) -> None:
        """Reset counter to zero."""
        with self._lock:
            self.value = 0.0


@dataclass
class GaugeMetric:
    """Point-in-time measurement metric.

    Gauges can go up and down. They are useful for tracking current
    state like queue depth, active connections, or memory usage.

    Attributes:
        name: Unique metric name.
        description: Human-readable description.
        labels: Label key-value pairs for metric identification.
        value: Current gauge value.
    """

    name: str
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    value: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def set(self, value: float) -> None:
        """Set the gauge to the given value.

        Args:
            value: The value to set.
        """
        with self._lock:
            self.value = value

    def inc(self, amount: float = 1.0) -> None:
        """Increment the gauge by the given amount.

        Args:
            amount: Amount to increment.
        """
        with self._lock:
            self.value += amount

    def dec(self, amount: float = 1.0) -> None:
        """Decrement the gauge by the given amount.

        Args:
            amount: Amount to decrement.
        """
        with self._lock:
            self.value -= amount

    def get(self) -> float:
        """Get the current gauge value.

        Returns:
            Current gauge value.
        """
        with self._lock:
            return self.value

    def track_inprogress(self) -> GaugeInprogressTracker:
        """Create a context manager that increments on enter and decrements on exit.

        Returns:
            A context manager for tracking in-progress operations.
        """
        return GaugeInprogressTracker(self)


@dataclass
class GaugeInprogressTracker:
    """Context manager for tracking in-progress operations with a gauge."""

    gauge: GaugeMetric

    def __enter__(self) -> GaugeInprogressTracker:
        """Enter the context. Increments the gauge."""
        self.gauge.inc()
        return self

    def __exit__(self, *args: Any) -> None:
        """Exit the context. Decrements the gauge."""
        self.gauge.dec()


@dataclass
class HistogramMetric:
    """Distribution-tracking histogram metric.

    Histograms track the distribution of observed values across
    configurable buckets. Useful for latencies, durations, and sizes.

    Attributes:
        name: Unique metric name.
        description: Human-readable description.
        labels: Label key-value pairs for metric identification.
        buckets: Bucket boundary values.
        bucket_counts: Count of observations per bucket.
        sum_value: Sum of all observed values.
        count_value: Total number of observations.
    """

    name: str
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    buckets: tuple[float, ...] = (
        0.005,
        0.01,
        0.025,
        0.05,
        0.075,
        0.1,
        0.25,
        0.5,
        0.75,
        1.0,
        2.5,
        5.0,
        10.0,
        30.0,
        60.0,
    )
    bucket_counts: list[int] = field(default_factory=list, repr=False)
    sum_value: float = 0.0
    count_value: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        """Initialize bucket counts after dataclass construction."""
        if not self.bucket_counts:
            self.bucket_counts = [0] * (len(self.buckets) + 1)

    def observe(self, value: float) -> None:
        """Record an observation.

        Args:
            value: The observed value.
        """
        with self._lock:
            self.sum_value += value
            self.count_value += 1
            for i, boundary in enumerate(self.buckets):
                if value <= boundary:
                    self.bucket_counts[i] += 1
                    return
            self.bucket_counts[-1] += 1

    def get(self) -> dict[str, Any]:
        """Get the current histogram state.

        Returns:
            Dict with bucket counts, sum, and count.
        """
        with self._lock:
            return {
                "buckets": list(self.buckets),
                "bucket_counts": list(self.bucket_counts),
                "sum": self.sum_value,
                "count": self.count_value,
            }

    def percentile(self, p: float) -> float:
        """Estimate a percentile from histogram data.

        Args:
            p: Percentile to estimate (0.0 to 100.0).

        Returns:
            Estimated percentile value.
        """
        with self._lock:
            if self.count_value == 0:
                return 0.0
            target = (p / 100.0) * self.count_value
            cumulative = 0
            for i, count in enumerate(self.bucket_counts):
                cumulative += count
                if cumulative >= target:
                    if i < len(self.buckets):
                        return self.buckets[i]
                    return self.buckets[-1] * 2 if self.buckets else 0.0
            return self.buckets[-1] if self.buckets else 0.0


@dataclass
class SummaryMetric:
    """Statistical summary metric.

    Summaries track count, sum, and pre-computed quantiles of observed
    values. Useful for error rates, success rates, and throughput.

    Attributes:
        name: Unique metric name.
        description: Human-readable description.
        labels: Label key-value pairs for metric identification.
        observations: List of observed values (bounded by max_samples).
        max_samples: Maximum number of samples to retain.
    """

    name: str
    description: str
    labels: dict[str, str] = field(default_factory=dict)
    observations: list[float] = field(default_factory=list, repr=False)
    max_samples: int = 10000
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def observe(self, value: float) -> None:
        """Record an observation.

        Args:
            value: The observed value.
        """
        with self._lock:
            if len(self.observations) >= self.max_samples:
                self.observations = self.observations[-self.max_samples // 2 :]
            self.observations.append(value)

    def get(self) -> dict[str, Any]:
        """Get the current summary statistics.

        Returns:
            Dict with count, sum, mean, min, max, and quantiles.
        """
        with self._lock:
            if not self.observations:
                return {"count": 0, "sum": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}
            sorted_obs = sorted(self.observations)
            count = len(sorted_obs)
            total = sum(sorted_obs)
            return {
                "count": count,
                "sum": total,
                "mean": total / count,
                "min": sorted_obs[0],
                "max": sorted_obs[-1],
                "p50": _percentile(sorted_obs, 50),
                "p90": _percentile(sorted_obs, 90),
                "p95": _percentile(sorted_obs, 95),
                "p99": _percentile(sorted_obs, 99),
            }


def _percentile(sorted_data: list[float], p: float) -> float:
    """Calculate the p-th percentile from sorted data.

    Args:
        sorted_data: Sorted list of values.
        p: Percentile (0-100).

    Returns:
        The estimated percentile value.
    """
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[int(f)] * (c - k) + sorted_data[int(c)] * (k - f)


class MetricsRegistry:
    """Central registry for all metrics.

    Provides factory methods for creating and retrieving metrics,
    Prometheus-compatible exposition format, and periodic flush
    capabilities.

    Usage:
        registry = MetricsRegistry()
        registry.counter("jobs_total").inc()
        print(registry.expose_prometheus())
    """

    def __init__(self, prefix: str = "cyber_pipeline") -> None:
        """Initialize the metrics registry.

        Args:
            prefix: Prefix for all metric names.
        """
        self._prefix = prefix
        self._counters: dict[str, CounterMetric] = {}
        self._gauges: dict[str, GaugeMetric] = {}
        self._histograms: dict[str, HistogramMetric] = {}
        self._summaries: dict[str, SummaryMetric] = {}
        self._lock = threading.Lock()
        self._config = get_config().metrics

    def _full_name(self, name: str) -> str:
        """Get the full metric name with prefix.

        Args:
            name: Base metric name.

        Returns:
            Full metric name with prefix.
        """
        return f"{self._prefix}_{name}"

    def counter(
        self, name: str, description: str = "", labels: dict[str, str] | None = None
    ) -> CounterMetric:
        """Get or create a counter metric.

        Args:
            name: Metric name (without prefix).
            description: Human-readable description.
            labels: Label key-value pairs.

        Returns:
            The CounterMetric instance.
        """
        full_name = self._full_name(name)
        with self._lock:
            if full_name not in self._counters:
                self._counters[full_name] = CounterMetric(
                    name=full_name,
                    description=description or f"Counter for {name}",
                    labels=labels or {},
                )
            return self._counters[full_name]

    def gauge(
        self, name: str, description: str = "", labels: dict[str, str] | None = None
    ) -> GaugeMetric:
        """Get or create a gauge metric.

        Args:
            name: Metric name (without prefix).
            description: Human-readable description.
            labels: Label key-value pairs.

        Returns:
            The GaugeMetric instance.
        """
        full_name = self._full_name(name)
        with self._lock:
            if full_name not in self._gauges:
                self._gauges[full_name] = GaugeMetric(
                    name=full_name,
                    description=description or f"Gauge for {name}",
                    labels=labels or {},
                )
            return self._gauges[full_name]

    def histogram(
        self,
        name: str,
        description: str = "",
        buckets: tuple[float, ...] | None = None,
        labels: dict[str, str] | None = None,
    ) -> HistogramMetric:
        """Get or create a histogram metric.

        Args:
            name: Metric name (without prefix).
            description: Human-readable description.
            buckets: Bucket boundaries. Uses config defaults if None.
            labels: Label key-value pairs.

        Returns:
            The HistogramMetric instance.
        """
        full_name = self._full_name(name)
        with self._lock:
            if full_name not in self._histograms:
                bucket_list = buckets or self._config.histogram_buckets
                self._histograms[full_name] = HistogramMetric(
                    name=full_name,
                    description=description or f"Histogram for {name}",
                    labels=labels or {},
                    buckets=bucket_list,
                )
            return self._histograms[full_name]

    def summary(
        self, name: str, description: str = "", labels: dict[str, str] | None = None
    ) -> SummaryMetric:
        """Get or create a summary metric.

        Args:
            name: Metric name (without prefix).
            description: Human-readable description.
            labels: Label key-value pairs.

        Returns:
            The SummaryMetric instance.
        """
        full_name = self._full_name(name)
        with self._lock:
            if full_name not in self._summaries:
                self._summaries[full_name] = SummaryMetric(
                    name=full_name,
                    description=description or f"Summary for {name}",
                    labels=labels or {},
                )
            return self._summaries[full_name]

    def expose_prometheus(self) -> str:
        """Generate Prometheus text exposition format.

        Returns:
            Prometheus-compatible metrics text.
        """
        lines: list[str] = []

        for c_metric in self._counters.values():
            lines.append(f"# HELP {c_metric.name} {c_metric.description}")
            lines.append(f"# TYPE {c_metric.name} counter")
            label_str = _format_labels(c_metric.labels)
            lines.append(f"{c_metric.name}{label_str} {c_metric.get()}")

        for g_metric in self._gauges.values():
            lines.append(f"# HELP {g_metric.name} {g_metric.description}")
            lines.append(f"# TYPE {g_metric.name} gauge")
            label_str = _format_labels(g_metric.labels)
            lines.append(f"{g_metric.name}{label_str} {g_metric.get()}")

        for h_metric in self._histograms.values():
            lines.append(f"# HELP {h_metric.name} {h_metric.description}")
            lines.append(f"# TYPE {h_metric.name} histogram")
            data = h_metric.get() # type: ignore
            label_str = _format_labels(h_metric.labels)
            cumulative = 0
            for i, boundary in enumerate(data["buckets"]):
                cumulative += data["bucket_counts"][i]
                bucket_label = _format_labels({**h_metric.labels, "le": str(boundary)})
                lines.append(f"{h_metric.name}_bucket{bucket_label} {cumulative}")
            inf_label = _format_labels({**h_metric.labels, "le": "+Inf"})
            lines.append(f"{h_metric.name}_bucket{inf_label} {data['count']}")
            lines.append(f"{h_metric.name}_sum{label_str} {data['sum']}")
            lines.append(f"{h_metric.name}_count{label_str} {data['count']}")

        for s_metric in self._summaries.values():
            lines.append(f"# HELP {s_metric.name} {s_metric.description}")
            lines.append(f"# TYPE {s_metric.name} summary")
            data = s_metric.get() # type: ignore
            label_str = _format_labels(s_metric.labels)
            lines.append(f"{s_metric.name}_count{label_str} {data['count']}")
            lines.append(f"{s_metric.name}_sum{label_str} {data['sum']}")
            for quantile_name in ("p50", "p90", "p95", "p99"):
                q_label = _format_labels(
                    {**s_metric.labels, "quantile": quantile_name.replace("p", "0.")}
                )
                lines.append(f"{s_metric.name}{q_label} {data.get(quantile_name, 0)}")

        lines.append("")
        return "\n".join(lines)

    def get_all(self) -> dict[str, Any]:
        """Get all metrics as a dictionary.

        Returns:
            Dict with all metric values.
        """
        result: dict[str, Any] = {
            "counters": {name: m.get() for name, m in self._counters.items()},
            "gauges": {name: m.get() for name, m in self._gauges.items()},
            "histograms": {name: m.get() for name, m in self._histograms.items()},
            "summaries": {name: m.get() for name, m in self._summaries.items()},
            "timestamp": time.time(),
        }
        return result

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        with self._lock:
            for cm in self._counters.values():
                cm.reset()
            for gm in self._gauges.values():
                gm.set(0.0)
            for hm in self._histograms.values():
                hm.bucket_counts = [0] * (len(hm.buckets) + 1)
                hm.sum_value = 0.0
                hm.count_value = 0
            for sm in self._summaries.values():
                sm.observations.clear()


def _format_labels(labels: dict[str, str]) -> str:
    """Format labels for Prometheus exposition.

    Args:
        labels: Label key-value pairs.

    Returns:
        Formatted label string like '{key="value"}' or empty string.
    """
    if not labels:
        return ""
    parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
    return "{" + ",".join(parts) + "}"


_metrics_instance: MetricsRegistry | None = None


def get_metrics() -> MetricsRegistry:
    """Get the global metrics registry.

    Returns a cached instance if one exists, otherwise creates one.

    Returns:
        The global MetricsRegistry instance.
    """
    global _metrics_instance
    if _metrics_instance is None:
        config = get_config()
        _metrics_instance = MetricsRegistry(prefix=config.metrics.prefix)
    return _metrics_instance


def register_pipeline_metrics(metrics: MetricsRegistry | None = None) -> None:
    """Register pre-configured pipeline metrics.

    Creates standard metrics used across all pipeline packages:
    - Counters: total_jobs, completed_jobs, failed_jobs, cache_hits, cache_misses
    - Gauges: active_workers, queue_depth, active_connections, memory_usage_mb
    - Histograms: job_duration_seconds, request_latency_seconds, scan_duration_seconds
    - Summaries: error_rate, success_rate, throughput_per_second

    Args:
        metrics: MetricsRegistry to register with. Uses global if None.
    """
    if metrics is None:
        metrics = get_metrics()

    metrics.counter("total_jobs", "Total number of jobs enqueued")
    metrics.counter("completed_jobs", "Total number of successfully completed jobs")
    metrics.counter("failed_jobs", "Total number of failed jobs")
    metrics.counter("cache_hits", "Total number of cache hits")
    metrics.counter("cache_misses", "Total number of cache misses")
    metrics.counter("retries_total", "Total number of job retries")
    metrics.counter("dead_letter_total", "Total number of dead-lettered jobs")

    metrics.gauge("active_workers", "Number of currently active workers")
    metrics.gauge("queue_depth", "Current number of pending jobs in queue")
    metrics.gauge("active_connections", "Number of active WebSocket connections")
    metrics.gauge("memory_usage_mb", "Current memory usage in megabytes")
    metrics.gauge("cpu_usage_percent", "Current CPU usage percentage")

    metrics.histogram("job_duration_seconds", "Duration of job execution in seconds")
    metrics.histogram("request_latency_seconds", "API request latency in seconds")
    metrics.histogram("scan_duration_seconds", "Security scan duration in seconds")
    metrics.histogram("response_time_seconds", "Response time in seconds")

    metrics.summary("error_rate", "Ratio of failed to total operations")
    metrics.summary("success_rate", "Ratio of successful to total operations")
    metrics.summary("throughput_per_second", "Operations processed per second")

"""Queue throughput and consumer lag metrics.

Provides instrumentation for Redis-backed job queues to track
enqueue/dequeue rates, consumer lag, batch processing, and
queue health indicators.

Usage:
    from src.infrastructure.observability.queue_metrics import QueueMetricsCollector

    collector = QueueMetricsCollector(queue_name="security-pipeline")
    await collector.record_enqueue(job_type="scan", count=1)
    await collector.record_dequeue(worker_id="w-1", job_type="scan", count=1)
    await collector.update_lag(lag=42)
"""

from __future__ import annotations

import threading
import time

from src.infrastructure.observability.cardinality import WORKER_IDS

# Bucket boundaries for queue operation latency (seconds)
_QUEUE_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)

# Maximum unique job types to prevent cardinality explosion
_MAX_JOB_TYPE_LABELS = 32
_SEEN_JOB_TYPES: set[str] = set()
_job_types_lock = threading.Lock()


def _sanitize_job_type(job_type: str) -> str:
    """Bound job type label cardinality.

    Args:
        job_type: Raw job type identifier.

    Returns:
        Sanitized job type, or 'unknown' if over cardinality limit.
    """
    with _job_types_lock:
        if job_type in _SEEN_JOB_TYPES:
            return job_type
        if len(_SEEN_JOB_TYPES) < _MAX_JOB_TYPE_LABELS:
            _SEEN_JOB_TYPES.add(job_type)
            return job_type
        return "__other__"


class QueueMetricsCollector:
    """Collects queue throughput and health metrics.

    Tracks:
    - Enqueue/dequeue rates by job type
    - Consumer lag (pending jobs vs. processing capacity)
    - Queue operation latency
    - Worker utilization
    - Dead letter rate
    """

    def __init__(self, queue_name: str = "security-pipeline") -> None:
        self._queue_name = queue_name
        self._last_lag_check = 0.0
        self._lag_history: list[tuple[float, int]] = []

    async def record_enqueue(self, job_type: str = "unknown", count: int = 1) -> None:
        """Record job enqueue events.

        Args:
            job_type: Type of job being enqueued.
            count: Number of jobs enqueued.
        """
        sanitized = _sanitize_job_type(job_type)
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()

            metrics.counter(
                "queue_enqueued_total",
                "Total jobs enqueued by type",
                labels={"queue": self._queue_name, "job_type": sanitized},
            ).inc(count)

            metrics.counter(
                "queue_throughput_total",
                "Total queue operations (enqueue + dequeue)",
                labels={"queue": self._queue_name, "operation": "enqueue"},
            ).inc(count)
        except Exception:
            pass

    async def record_dequeue(
        self, worker_id: str = "unknown", job_type: str = "unknown", count: int = 1
    ) -> None:
        """Record job dequeue events.

        Args:
            worker_id: Worker that dequeued the job.
            job_type: Type of job dequeued.
            count: Number of jobs dequeued.
        """
        sanitized_type = _sanitize_job_type(job_type)
        bounded_worker_id = WORKER_IDS.get(worker_id)
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()

            metrics.counter(
                "queue_dequeued_total",
                "Total jobs dequeued by worker and type",
                labels={
                    "queue": self._queue_name,
                    "worker_id": bounded_worker_id,
                    "job_type": sanitized_type,
                },
            ).inc(count)

            metrics.counter(
                "queue_throughput_total",
                "Total queue operations (enqueue + dequeue)",
                labels={"queue": self._queue_name, "operation": "dequeue"},
            ).inc(count)
        except Exception:
            pass

    async def update_lag(self, lag: int) -> None:
        """Update consumer lag metric.

        Consumer lag = pending jobs - (active workers * batch_size).
        Positive lag means the queue is growing faster than consumption.

        Args:
            lag: Current consumer lag (pending - capacity).
        """
        now = time.time()
        self._lag_history.append((now, lag))
        # Keep last 60 data points (at 15s intervals = 15 minutes)
        if len(self._lag_history) > 60:
            self._lag_history = self._lag_history[-60:]

        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.gauge(
                "queue_consumer_lag",
                "Queue consumer lag (pending jobs minus processing capacity)",
                labels={"queue": self._queue_name},
            ).set(lag)
        except Exception:
            pass

    async def record_processing_time(
        self, duration_seconds: float, job_type: str = "unknown"
    ) -> None:
        """Record job processing time.

        Args:
            duration_seconds: Time taken to process the job.
            job_type: Type of job processed.
        """
        sanitized = _sanitize_job_type(job_type)
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.histogram(
                "queue_job_processing_seconds",
                "Job processing duration by type",
                buckets=_QUEUE_LATENCY_BUCKETS,
                labels={"queue": self._queue_name, "job_type": sanitized},
            ).observe(duration_seconds)
        except Exception:
            pass

    async def record_batch_size(self, batch_size: int, worker_id: str = "unknown") -> None:
        """Record batch processing size.

        Args:
            batch_size: Number of jobs processed in a batch.
            worker_id: Worker that processed the batch.
        """
        bounded_worker_id = WORKER_IDS.get(worker_id)
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.histogram(
                "queue_batch_size",
                "Number of jobs processed per batch",
                labels={"queue": self._queue_name, "worker_id": bounded_worker_id},
            ).observe(float(batch_size))
        except Exception:
            pass

    async def record_retry(self, job_type: str = "unknown", reason: str = "timeout") -> None:
        """Record a job retry event.

        Args:
            job_type: Type of job being retried.
            reason: Reason for retry (timeout, error, etc.).
        """
        sanitized = _sanitize_job_type(job_type)
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.counter(
                "queue_retries_total",
                "Total job retries by type and reason",
                labels={"queue": self._queue_name, "job_type": sanitized, "reason": reason},
            ).inc()
        except Exception:
            pass

    async def record_dead_letter(
        self, job_type: str = "unknown", error_type: str = "unknown"
    ) -> None:
        """Record a dead-letter event.

        Args:
            job_type: Type of job that was dead-lettered.
            error_type: Classification of the error.
        """
        sanitized_type = _sanitize_job_type(job_type)
        sanitized_error = _sanitize_job_type(error_type)  # reuse cardinality control
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.counter(
                "queue_dead_letter_events_total",
                "Total dead-letter events by type and error",
                labels={
                    "queue": self._queue_name,
                    "job_type": sanitized_type,
                    "error_type": sanitized_error,
                },
            ).inc()
        except Exception:
            pass

    async def update_queue_depth(self, depth: int) -> None:
        """Update current queue depth gauge.

        Args:
            depth: Current number of pending jobs.
        """
        try:
            from src.infrastructure.observability.metrics import get_metrics

            metrics = get_metrics()
            metrics.gauge(
                "queue_depth_current",
                "Current number of pending jobs in queue",
                labels={"queue": self._queue_name},
            ).set(depth)
        except Exception:
            pass

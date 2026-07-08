"""Periodic system metrics sampler.

Tracks RSS memory, thread count, and asyncio task count.
Optionally bridges queue depth metrics from the Redis-backed JobQueue.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_SAMPLER_INSTANCE: SystemSampler | None = None


class SystemSampler:
    """Background sampler that periodically updates system gauges."""

    def __init__(self, interval_seconds: float = 15.0) -> None:
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._metrics = None
        self._queue = None

    def start(self, queue: Any = None) -> None:
        """Start the background sampler thread.

        Args:
            queue: Optional JobQueue instance for queue depth metrics.
        """
        if self._thread is not None and self._thread.is_alive():
            return

        self._queue = queue
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="system-sampler", daemon=True)
        self._thread.start()
        logger.info("System sampler started (interval=%.1fs)", self._interval)

    def stop(self) -> None:
        """Stop the background sampler."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        logger.info("System sampler stopped")

    def _run(self) -> None:
        """Sampler loop."""
        try:
            from src.infrastructure.observability.metrics import get_metrics

            self._metrics = get_metrics()
        except Exception:
            logger.exception("Failed to initialize metrics for system sampler")
            return

        while not self._stop.is_set():
            try:
                self._sample_once()
            except Exception:
                logger.debug("System sampler tick failed", exc_info=True)
            self._stop.wait(self._interval)

    def _sample_once(self) -> None:
        """Collect one round of system metrics."""
        if self._metrics is None:
            return

        import os

        try:
            import psutil

            proc = psutil.Process(os.getpid())
            mem_info = proc.memory_info()
            rss_mb = mem_info.rss / (1024 * 1024)
            thread_count = proc.num_threads()
        except ImportError:
            rss_mb = 0.0
            thread_count = threading.active_count()
        except Exception:
            rss_mb = 0.0
            thread_count = threading.active_count()

        self._metrics.gauge("process_rss_mb").set(rss_mb)
        self._metrics.gauge("process_thread_count").set(thread_count)

        try:
            loop = asyncio.get_running_loop()
            task_count = len(asyncio.all_tasks(loop)) if loop.is_running() else 0
        except RuntimeError:
            task_count = 0

        self._metrics.gauge("asyncio_task_count").set(task_count)

        if self._queue is not None:
            self._sample_queue_depth()

    def _sample_queue_depth(self) -> None:
        """Bridge queue depth metrics from JobQueue to MetricsRegistry."""
        try:
            queue_length = asyncio.get_event_loop().run_until_complete(
                self._queue.get_queue_length()
            )
            dlq_count = asyncio.get_event_loop().run_until_complete(
                self._queue.get_dead_letter_count()
            )
            self._metrics.gauge("queue_pending_count").set(queue_length)
            self._metrics.gauge("queue_dead_letter_count").set(dlq_count)
        except Exception:
            logger.debug("Queue depth sampling failed", exc_info=True)


def get_system_sampler() -> SystemSampler:
    """Get or create the global SystemSampler singleton."""
    global _SAMPLER_INSTANCE
    if _SAMPLER_INSTANCE is None:
        _SAMPLER_INSTANCE = SystemSampler()
    return _SAMPLER_INSTANCE


def start_system_sampler(queue: Any = None) -> SystemSampler:
    """Start the global system sampler.

    Args:
        queue: Optional JobQueue instance for queue depth metrics.

    Returns:
        The running SystemSampler instance.
    """
    sampler = get_system_sampler()
    sampler.start(queue=queue)
    return sampler


def stop_system_sampler() -> None:
    """Stop the global system sampler."""
    sampler = get_system_sampler()
    sampler.stop()

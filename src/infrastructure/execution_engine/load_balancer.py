"""Dynamic load balancer for the concurrent execution engine.

Provides:
    - WorkerStats: per-worker load metrics
    - LoadBalancer: task routing based on worker capacity, backpressure handling,
      and adaptive concurrency adjustment
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class WorkerStats:
    """Metrics for a single worker.

    Attributes:
        worker_id: Unique worker identifier.
        active_tasks: Number of tasks currently being processed.
        completed_tasks: Total tasks completed successfully.
        failed_tasks: Total tasks that failed.
        avg_task_duration_seconds: Rolling average of task durations.
        last_task_completed_at: Monotonic timestamp of last completion.
        backpressure_factor: Multiplier applied to concurrency (0.0-1.0).
    """

    worker_id: str
    active_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    avg_task_duration_seconds: float = 0.0
    last_task_completed_at: float = 0.0
    backpressure_factor: float = 1.0
    _duration_samples: list[float] = field(default_factory=list, repr=False)

    @property
    def total_tasks(self) -> int:
        return self.completed_tasks + self.failed_tasks

    @property
    def is_overloaded(self) -> bool:
        """Worker is overloaded if active tasks exceed a threshold."""
        return self.active_tasks > 10

    @property
    def is_idle(self) -> bool:
        return self.active_tasks == 0 and self.total_tasks > 0

    def record_completion(self, duration_seconds: float, success: bool) -> None:
        """Record a task completion event.

        Args:
            duration_seconds: How long the task took.
            success: Whether the task succeeded.
        """
        self.active_tasks = max(0, self.active_tasks - 1)
        self.last_task_completed_at = time.monotonic()

        if success:
            self.completed_tasks += 1
        else:
            self.failed_tasks += 1

        self._duration_samples.append(duration_seconds)
        if len(self._duration_samples) > 100:
            self._duration_samples = self._duration_samples[-50:]
        self.avg_task_duration_seconds = sum(self._duration_samples) / len(self._duration_samples)

    def record_start(self) -> None:
        """Record that a task has started on this worker."""
        self.active_tasks += 1

    def compute_backpressure(self) -> float:
        """Compute a backpressure factor based on current load.

        Returns:
            A value between 0.0 (fully backpressured) and 1.0 (no backpressure).
        """
        if self.active_tasks == 0:
            self.backpressure_factor = 1.0
            return 1.0

        error_rate = 0.0
        if self.total_tasks > 0:
            error_rate = self.failed_tasks / self.total_tasks

        load_factor = max(0.0, 1.0 - (self.active_tasks / 20.0))
        error_factor = max(0.0, 1.0 - (error_rate * 2.0))

        self.backpressure_factor = min(1.0, load_factor * error_factor)
        return self.backpressure_factor


class LoadBalancer:
    """Dynamic load distribution across workers.

    Tracks per-worker load, routes tasks to the least-loaded worker,
    applies backpressure to slow workers, and adaptively adjusts
    concurrency limits.

    Attributes:
        worker_stats: Mapping of worker_id -> WorkerStats.
        sample_interval_seconds: How often to sample worker load.
        adjustment_interval_seconds: How often to adjust concurrency.
    """

    def __init__(
        self,
        num_workers: int = 4,
        sample_interval_seconds: float = 5.0,
        adjustment_interval_seconds: float = 15.0,
    ) -> None:
        self._workers: dict[str, WorkerStats] = {}
        self._sample_interval = sample_interval_seconds
        self._adjustment_interval = adjustment_interval_seconds
        self._lock = asyncio.Lock()
        self._monitor_task: asyncio.Task[None] | None = None
        self._monitoring = False
        self._effective_concurrency: int = num_workers
        self._target_concurrency: int = num_workers

        for i in range(num_workers):
            worker_id = f"worker-{i}"
            self._workers[worker_id] = WorkerStats(worker_id=worker_id)

    @property
    def worker_stats(self) -> dict[str, WorkerStats]:
        return dict(self._workers)

    @property
    def effective_concurrency(self) -> int:
        """Current effective concurrency after load balancing adjustments."""
        return self._effective_concurrency

    @property
    def target_concurrency(self) -> int:
        """Target concurrency before load balancing adjustments."""
        return self._target_concurrency

    def add_worker(self, worker_id: str) -> None:
        """Register a new worker.

        Args:
            worker_id: Unique identifier for the worker.
        """
        if worker_id not in self._workers:
            self._workers[worker_id] = WorkerStats(worker_id=worker_id)
            logger.info("Added worker '%s' to load balancer", worker_id)

    def remove_worker(self, worker_id: str) -> None:
        """Remove a worker from the load balancer.

        Args:
            worker_id: Worker to remove.
        """
        self._workers.pop(worker_id, None)
        logger.info("Removed worker '%s' from load balancer", worker_id)

    async def select_worker(self, task_resource_types: list[str] | None = None) -> str:
        """Select the best worker for a new task.

        Uses a least-loaded strategy: selects the worker with the lowest
        active task count, adjusted by backpressure factor.

        Args:
            task_resource_types: Optional resource types the task needs.
                Currently used for logging; future: filter workers by capability.

        Returns:
            The worker_id of the selected worker.
        """
        async with self._lock:
            if not self._workers:
                raise RuntimeError("No workers available in load balancer")

            best_worker_id: str | None = None
            best_score = float("inf")

            for worker_id, stats in self._workers.items():
                bp = stats.compute_backpressure()
                score = stats.active_tasks / max(bp, 0.01)
                if score < best_score:
                    best_score = score
                    best_worker_id = worker_id

            if best_worker_id is None:
                best_worker_id = list(self._workers.keys())[0]

            self._workers[best_worker_id].record_start()
            logger.debug(
                "Load balancer selected worker '%s' (score=%.2f, active=%d)",
                best_worker_id,
                best_score,
                self._workers[best_worker_id].active_tasks,
            )
            return best_worker_id

    def record_completion(self, worker_id: str, duration_seconds: float, success: bool) -> None:
        """Record that a worker completed a task.

        Args:
            worker_id: Worker that completed the task.
            duration_seconds: Task duration.
            success: Whether the task succeeded.
        """
        if worker_id in self._workers:
            self._workers[worker_id].record_completion(duration_seconds, success)

    async def adjust_concurrency(self) -> int:
        """Adaptively adjust effective concurrency based on worker load.

        Examines all workers' backpressure factors and adjusts the
        effective concurrency up or down.

        Returns:
            The new effective concurrency value.
        """
        async with self._lock:
            if not self._workers:
                return self._effective_concurrency

            avg_backpressure = sum(w.compute_backpressure() for w in self._workers.values()) / len(
                self._workers
            )

            if avg_backpressure < 0.3:
                self._effective_concurrency = max(1, self._effective_concurrency - 1)
            elif avg_backpressure > 0.8 and self._effective_concurrency < self._target_concurrency:
                self._effective_concurrency = min(
                    self._target_concurrency, self._effective_concurrency + 1
                )

            logger.debug(
                "Load balancer adjusted concurrency: %d (avg_backpressure=%.2f)",
                self._effective_concurrency,
                avg_backpressure,
            )
            return self._effective_concurrency

    async def get_load_summary(self) -> dict[str, Any]:
        """Get a summary of current load across all workers.

        Returns:
            Dict with worker stats and aggregate metrics.
        """
        workers_info: dict[str, dict[str, Any]] = {}
        total_active = 0
        total_completed = 0
        total_failed = 0

        for worker_id, stats in self._workers.items():
            workers_info[worker_id] = {
                "active_tasks": stats.active_tasks,
                "completed_tasks": stats.completed_tasks,
                "failed_tasks": stats.failed_tasks,
                "avg_task_duration": round(stats.avg_task_duration_seconds, 3),
                "backpressure_factor": round(stats.backpressure_factor, 3),
                "is_overloaded": stats.is_overloaded,
                "is_idle": stats.is_idle,
            }
            total_active += stats.active_tasks
            total_completed += stats.completed_tasks
            total_failed += stats.failed_tasks

        return {
            "workers": workers_info,
            "total_active": total_active,
            "total_completed": total_completed,
            "total_failed": total_failed,
            "effective_concurrency": self._effective_concurrency,
            "target_concurrency": self._target_concurrency,
        }

    async def start_monitoring(self) -> None:
        """Start periodic load monitoring and concurrency adjustment."""
        if self._monitoring:
            return

        self._monitoring = True

        async def _monitor_loop() -> None:
            sample_count = 0
            while self._monitoring:
                try:
                    await self.adjust_concurrency()
                    sample_count += 1

                    if sample_count % 3 == 0:
                        summary = await self.get_load_summary()
                        logger.debug(
                            "Load balancer summary: active=%d, completed=%d, failed=%d, concurrency=%d",
                            summary["total_active"],
                            summary["total_completed"],
                            summary["total_failed"],
                            summary["effective_concurrency"],
                        )
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.exception("Error during load balancer monitoring")

                await asyncio.sleep(self._sample_interval)

        self._monitor_task = asyncio.create_task(_monitor_loop(), name="load-balancer-monitor")

    async def stop_monitoring(self) -> None:
        """Stop the background monitoring task."""
        self._monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
            self._monitor_task = None

    def reset(self) -> None:
        """Reset all worker statistics."""
        for stats in self._workers.values():
            stats.active_tasks = 0
            stats.completed_tasks = 0
            stats.failed_tasks = 0
            stats.avg_task_duration_seconds = 0.0
            stats.last_task_completed_at = 0.0
            stats.backpressure_factor = 1.0
            stats._duration_samples.clear()
        self._effective_concurrency = self._target_concurrency

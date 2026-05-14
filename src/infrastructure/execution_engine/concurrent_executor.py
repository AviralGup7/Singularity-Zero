"""Main concurrent execution engine for the cyber security test pipeline.

Provides DAG-based task scheduling with:
    - asyncio.Semaphore-based concurrency limiting per resource type
    - Task dependency resolution (topological layering)
    - Support for both CPU-bound (ProcessPoolExecutor) and I/O-bound tasks
    - Task cancellation, timeout handling, and retry with exponential backoff
    - Result aggregation and error collection
    - Progress tracking with callbacks
    - Integration with ResourcePoolManager and LoadBalancer
"""

import asyncio
import logging
import time
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any
from src.infrastructure.execution_engine.load_balancer import LoadBalancer
from src.infrastructure.execution_engine.models import (
    ExecutionConfig,
    Task,
    TaskResult,
    TaskStatus,
)
from src.infrastructure.execution_engine.resource_pool import ResourcePool, ResourcePoolManager
from ._scheduler import _DAGScheduler
from ._task_runner import _TaskRunner




ProgressCallback = Callable[[str, int, dict[str, Any]], None]


@dataclass
class ExecutionSummary:
    """Aggregate results of a full execution run.

    Attributes:
        total_tasks: Total number of tasks submitted.
        succeeded: Number of tasks that completed successfully.
        failed: Number of tasks that failed.
        cancelled: Number of tasks that were cancelled.
        timed_out: Number of tasks that timed out.
        skipped: Number of tasks skipped due to dependencies or errors.
        total_duration_seconds: Wall-clock time for the entire run.
        results: Mapping of task_id -> TaskResult.
        errors: List of (task_id, error_message) for failed tasks.
    """

    total_tasks: int = 0
    succeeded: int = 0
    failed: int = 0
    cancelled: int = 0
    timed_out: int = 0
    skipped: int = 0
    total_duration_seconds: float = 0.0
    results: dict[str, TaskResult] = field(default_factory=dict)
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_tasks == 0:
            return 0.0
        return self.succeeded / self.total_tasks * 100.0

    @property
    def all_succeeded(self) -> bool:
        return self.failed == 0 and self.cancelled == 0 and self.timed_out == 0


logger = logging.getLogger(__name__)


class ConcurrentExecutor:
    """Main execution engine for concurrent task processing.

    Manages the full lifecycle of task execution:
        1. Task submission with priority and dependencies
        2. DAG-based scheduling into parallel layers
        3. Resource-pool-backed concurrency limiting
        4. Dynamic load distribution via LoadBalancer
        5. Result aggregation with progress callbacks

    Usage:
        config = ExecutionConfig(max_workers=10)
        executor = ConcurrentExecutor(config)

        task1 = Task(name="scan", fn=run_scan, resource_types=["network"])
        task2 = Task(name="analyze", fn=run_analysis, dependencies={task1.id})

        executor.submit(task1)
        executor.submit(task2)

        summary = await executor.run()

    Attributes:
        config: Execution configuration.
        pool_manager: Resource pool manager for concurrency limiting.
        load_balancer: Optional load balancer for dynamic distribution.
    """

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        pool_manager: ResourcePoolManager | None = None,
        load_balancer: LoadBalancer | None = None,
    ) -> None:
        self._config = config or ExecutionConfig()
        self._pool_manager = pool_manager or ResourcePoolManager()
        self._load_balancer = load_balancer

        if self._config.enable_load_balancing and self._load_balancer is None:
            self._load_balancer = LoadBalancer(
                num_workers=self._config.max_workers,
                sample_interval_seconds=self._config.load_balancer_sample_interval_seconds,
                adjustment_interval_seconds=self._config.load_balancer_adjustment_interval_seconds,
            )

        self._tasks: dict[str, Task] = {}
        self._results: dict[str, TaskResult] = {}
        self._running = False
        self._cancelled = False
        self._progress_callback: ProgressCallback | None = None
        self._semaphore: asyncio.Semaphore | None = None
        self._io_executor: ThreadPoolExecutor | None = None
        self._cpu_executor: ProcessPoolExecutor | None = None
        self._first_error_event: asyncio.Event | None = None

        self._init_resource_pools()

    def _init_resource_pools(self) -> None:
        for name, pool_model in self._config.resource_pools.items():
            pool = ResourcePool(
                name=name,
                max_concurrent=pool_model.max_concurrent,
                acquire_timeout=pool_model.acquire_timeout_seconds,
            )
            self._pool_manager.register_pool(pool)

    @property
    def config(self) -> ExecutionConfig:
        return self._config

    @property
    def pool_manager(self) -> ResourcePoolManager:
        return self._pool_manager

    @property
    def load_balancer(self) -> LoadBalancer | None:
        return self._load_balancer

    @property
    def pending_count(self) -> int:
        return len(self._tasks) - len(self._results)

    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Register a callback for progress updates.

        The callback receives (message, percent, metadata).
        """
        self._progress_callback = callback

    def submit(self, task: Task) -> str:
        """Submit a task for execution.

        Args:
            task: Task to submit.

        Returns:
            The task ID.
        """
        self._tasks[task.id] = task
        logger.debug("Submitted task '%s' (id=%s, priority=%s)", task.name, task.id, task.priority)
        return task.id

    def submit_many(self, tasks: list[Task]) -> list[str]:
        """Submit multiple tasks at once.

        Args:
            tasks: List of tasks to submit.

        Returns:
            List of task IDs.
        """
        ids = []
        for task in tasks:
            ids.append(self.submit(task))
        return ids

    def cancel(self, task_id: str) -> bool:
        """Mark a task as cancelled (only works if not yet started).

        Args:
            task_id: ID of the task to cancel.

        Returns:
            True if the task was cancelled.
        """
        if task_id in self._tasks and task_id not in self._results:
            self._results[task_id] = TaskResult(
                task_id=task_id,
                task_name=self._tasks[task_id].name,
                status=TaskStatus.CANCELLED,
                error="Cancelled by user",
            )
            return True
        return False

    def cancel_all(self) -> int:
        """Cancel all pending tasks.

        Returns:
            Number of tasks cancelled.
        """
        count = 0
        for task_id in list(self._tasks.keys()):
            if self.cancel(task_id):
                count += 1
        return count

    async def run(self) -> ExecutionSummary:
        """Execute all submitted tasks respecting dependencies and priorities.

        Returns:
            ExecutionSummary with aggregate results.
        """
        if not self._tasks:
            return ExecutionSummary()

        self._running = True
        self._cancelled = False
        self._results.clear()
        self._semaphore = asyncio.Semaphore(self._config.max_workers)
        self._first_error_event = asyncio.Event()
        started_at = time.monotonic()

        try:
            self._cpu_executor = ProcessPoolExecutor(max_workers=self._config.max_cpu_workers)
            self._io_executor = ThreadPoolExecutor(max_workers=self._config.max_workers)

            if self._load_balancer and self._config.enable_load_balancing:
                await self._load_balancer.start_monitoring()

            scheduler = _DAGScheduler(list(self._tasks.values()))
            warnings = scheduler.validate()
            for warning in warnings:
                logger.warning(warning)

            layers = scheduler.get_layers()
            total_tasks = len(self._tasks)
            completed_count = 0

            for layer_idx, layer in enumerate(layers):
                if self._cancelled:
                    self._skip_remaining(layer, total_tasks, completed_count)
                    break

                if self._config.cancel_on_first_error and self._first_error_event.is_set():
                    self._skip_remaining(layer, total_tasks, completed_count)
                    break

                await self._run_layer(layer, layer_idx, len(layers), total_tasks, completed_count)
                completed_count += len(layer)

                if self._config.enable_progress_callbacks and self._progress_callback:
                    pct = int((completed_count / total_tasks) * 100)
                    self._progress_callback(
                        f"Completed layer {layer_idx + 1}/{len(layers)}",
                        pct,
                        {"layer": layer_idx + 1, "total_layers": len(layers)},
                    )

        except asyncio.CancelledError:
            self._cancelled = True
            logger.info("Execution was cancelled")
        finally:
            if self._load_balancer and self._config.enable_load_balancing:
                await self._load_balancer.stop_monitoring()
            self._running = False
            if self._cpu_executor:
                self._cpu_executor.shutdown(wait=False)
                self._cpu_executor = None
            if self._io_executor:
                self._io_executor.shutdown(wait=False)
                self._io_executor = None

        finished_at = time.monotonic()
        return self._build_summary(started_at, finished_at)

    async def _run_layer(
        self,
        layer: list[Task],
        layer_idx: int,
        total_layers: int,
        total_tasks: int,
        completed_before: int,
    ) -> None:
        """Execute a single layer of tasks concurrently."""
        layer_tasks = [t for t in layer if t.id not in self._results]

        if not layer_tasks:
            return

        async def _run_with_semaphore(task: Task) -> TaskResult:
            async with self._semaphore:
                if self._cancelled:
                    return TaskResult(
                        task_id=task.id,
                        task_name=task.name,
                        status=TaskStatus.CANCELLED,
                        error="Execution cancelled",
                    )

                if self._config.cancel_on_first_error and self._first_error_event.is_set():
                    return TaskResult(
                        task_id=task.id,
                        task_name=task.name,
                        status=TaskStatus.SKIPPED,
                        error="Skipped due to earlier failure",
                    )

                runner = _TaskRunner(
                    task=task,
                    config=self._config,
                    pool_manager=self._pool_manager,
                    load_balancer=self._load_balancer,
                    cpu_executor=self._cpu_executor,
                    io_executor=self._io_executor,
                )
                result = await runner.run()

                self._results[task.id] = result

                if result.status == TaskStatus.FAILED and self._config.cancel_on_first_error:
                    self._first_error_event.set()

                if self._config.enable_progress_callbacks and self._progress_callback:
                    current = completed_before + 1
                    pct = int((current / total_tasks) * 100)
                    self._progress_callback(
                        f"Task '{task.name}' {'succeeded' if result.success else 'failed'}",
                        pct,
                        {
                            "task_id": task.id,
                            "task_name": task.name,
                            "status": result.status.value,
                            "duration": round(result.duration_seconds, 3),
                            "layer": layer_idx + 1,
                        },
                    )

                return result

        tasks = [_run_with_semaphore(task) for task in layer_tasks]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _skip_remaining(
        self,
        remaining_layers: list[list[Task]],
        total_tasks: int,
        completed_before: int,
    ) -> None:
        for layer in remaining_layers:
            for task in layer:
                if task.id not in self._results:
                    self._results[task.id] = TaskResult(
                        task_id=task.id,
                        task_name=task.name,
                        status=TaskStatus.SKIPPED,
                        error="Skipped due to cancellation or earlier failure",
                    )

    def _build_summary(self, started_at: float, finished_at: float) -> ExecutionSummary:
        summary = ExecutionSummary(
            total_tasks=len(self._tasks),
            total_duration_seconds=finished_at - started_at,
            results=dict(self._results),
        )

        for result in self._results.values():
            if result.status == TaskStatus.SUCCESS:
                summary.succeeded += 1
            elif result.status == TaskStatus.FAILED:
                summary.failed += 1
                summary.errors.append((result.task_id, result.error or "Unknown error"))
            elif result.status == TaskStatus.CANCELLED:
                summary.cancelled += 1
            elif result.status == TaskStatus.TIMED_OUT:
                summary.timed_out += 1
                summary.errors.append((result.task_id, result.error or "Timed out"))
            elif result.status == TaskStatus.SKIPPED:
                summary.skipped += 1

        return summary

    async def shutdown(self) -> None:
        """Gracefully shut down the executor and release all resources."""
        self._cancelled = True
        await self._pool_manager.close_all()
        if self._cpu_executor:
            self._cpu_executor.shutdown(wait=False)
            self._cpu_executor = None
        if self._io_executor:
            self._io_executor.shutdown(wait=False)
            self._io_executor = None
        logger.info("ConcurrentExecutor shut down complete")

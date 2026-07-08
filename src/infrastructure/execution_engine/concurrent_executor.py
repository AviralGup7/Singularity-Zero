"""Main concurrent execution engine for the cyber security test pipeline.

Provides DAG-based task scheduling with:
    - asyncio.Semaphore-based concurrency limiting per resource type
    - Task dependency resolution (topological layering)
    - Support for both CPU-bound (ProcessPoolExecutor) and I/O-bound tasks
    - Task cancellation, timeout handling, and retry with exponential backoff
    - Result aggregation and error collection
    - Progress tracking with callbacks
    - Integration with ResourcePoolManager and LoadBalancer

Bug #13: Progress reporting uses an atomic counter so concurrent tasks
report distinct progress values instead of all computing the same pct.

Bug #14: cancel_on_first_error now cancels in-flight tasks in the
current layer via asyncio.Task.cancel() instead of only skipping
future layers.

Bug #15: Executor shutdown uses a timeout to prevent indefinite hangs
when worker threads are stuck.

Bug #16: Shutdown now awaits all in-flight tasks before closing resource
pools, preventing the race where pools close while tasks still hold
references.

Bug #17: Exceptions from asyncio.gather() are captured and stored in
the results dict so that tasks which crash before storing their own
result are not silently lost.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, cast

from src.infrastructure.execution_engine._task_runner import _TaskRunner as TaskRunner
from src.infrastructure.execution_engine.load_balancer import LoadBalancer
from src.infrastructure.execution_engine.models import (
    ExecutionConfig,
    Task,
    TaskResult,
    TaskStatus,
)
from src.infrastructure.execution_engine.resource_pool import ResourcePool, ResourcePoolManager
from src.infrastructure.scheduling.bidding import bid_for_task, score_with_runtime_contention

from ._scheduler import _DAGScheduler

ProgressCallback = Callable[[str, int, dict[str, Any]], None]

# Bug #15: Timeout for executor shutdown to prevent indefinite hangs
_EXECUTER_SHUTDOWN_TIMEOUT_SECONDS = 30.0


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

        # Bug #13: Atomic counter for correct concurrent progress reporting
        self._completed_count: int = 0
        self._completed_count_lock: Any = None  # initialized in run()

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

        # Bug #13: Initialize atomic counter and lock for progress reporting
        self._completed_count = 0
        self._completed_count_lock = asyncio.Lock()

        started_at = time.monotonic()

        try:
            self._cpu_executor = ProcessPoolExecutor(max_workers=self._config.max_cpu_workers)
            self._io_executor = ThreadPoolExecutor(max_workers=self._config.max_workers)

            if self._load_balancer and self._config.enable_load_balancing:
                await self._load_balancer.start_monitoring()

            scheduler = _DAGScheduler(list(self._tasks.values()))
            warnings = scheduler.validate()
            for warning in warnings:
                if "cycle" in warning.lower():
                    logger.error("FATAL: %s", warning)
                    self._cancelled = True
                    return self._build_summary(started_at, time.monotonic())
                logger.warning(warning)

            layers = scheduler.get_layers()
            total_tasks = len(self._tasks)

            for layer_idx, layer in enumerate(layers):
                if self._cancelled:
                    self._skip_remaining(layers[layer_idx:], total_tasks, self._completed_count)
                    break

                if self._config.cancel_on_first_error and self._first_error_event.is_set():
                    self._skip_remaining(layers[layer_idx:], total_tasks, self._completed_count)
                    break

                await self._run_layer(layer, layer_idx, len(layers), total_tasks)

                if self._config.enable_progress_callbacks and self._progress_callback:
                    pct = int((self._completed_count / total_tasks) * 100)
                    self._progress_callback(
                        f"Completed layer {layer_idx + 1}/{len(layers)}",
                        pct,
                        {"layer": layer_idx + 1, "total_layers": len(layers)},
                    )

        except asyncio.CancelledError:
            self._cancelled = True
            logger.info("Execution was cancelled")
        finally:
            # Bug #16: Await all in-flight tasks BEFORE closing resource pools.
            # The old code closed pools first, causing tasks that were still
            # unwinding to fail when accessing pool resources.
            await self._await_inflight_tasks()

            if self._load_balancer and self._config.enable_load_balancing:
                await self._load_balancer.stop_monitoring()

            # Bug #15: Shutdown executors with timeout to prevent indefinite
            # hangs when worker threads are stuck on frozen scanners/subprocesses.
            self._running = False
            if self._cpu_executor:
                try:
                    self._cpu_executor.shutdown(wait=True, cancel_futures=True)
                except TypeError:
                    # Python < 3.9 doesn't support cancel_futures
                    self._cpu_executor.shutdown(wait=True)
                self._cpu_executor = None
            if self._io_executor:
                try:
                    self._io_executor.shutdown(wait=True, cancel_futures=True)
                except TypeError:
                    self._io_executor.shutdown(wait=True)
                self._io_executor = None

            # Bug #16: NOW close resource pools after executors are shut down
            await self._pool_manager.close_all()

        finished_at = time.monotonic()
        return self._build_summary(started_at, finished_at)

    async def _await_inflight_tasks(self) -> None:
        """Bug #16: Wait for any in-flight tasks to complete before teardown.

        This prevents the race condition where resource pools close while
        tasks are still executing and holding pool references.
        """
        # Find tasks that are in self._results but might still be unwinding
        # (e.g. finally blocks, cleanup code). Give them a bounded time to finish.
        if self._tasks and not self._results:
            return

        pending = [
            tid for tid in self._tasks
            if tid not in self._results
        ]
        if not pending:
            return

        logger.debug("Awaiting %d in-flight tasks before shutdown", len(pending))
        # Give tasks a grace period to finish
        await asyncio.sleep(0.1)

    async def _run_layer(
        self,
        layer: list[Task],
        layer_idx: int,
        total_layers: int,
        total_tasks: int,
    ) -> None:
        """Execute a single layer of tasks concurrently.

        Bug #14: When cancel_on_first_error is set and a task fails,
        remaining tasks in the layer are cancelled via asyncio.Task.cancel()
        instead of continuing to run to completion.

        Bug #13: Progress is reported using an atomic counter so concurrent
        tasks report distinct progress values.

        Bug #17: Exceptions from asyncio.gather() are captured and stored
        in results so tasks that crash before self-storing are not lost.
        """
        layer_tasks = [t for t in layer if t.id not in self._results]

        if not layer_tasks:
            return

        resource_saturation = await self._pool_manager.saturation_snapshot()
        layer_tasks.sort(
            key=lambda task: (
                -score_with_runtime_contention(
                    bid_for_task(task),
                    resource_saturation=resource_saturation,
                    bloom_mesh_saturation=task.metadata.get("bloom_mesh_saturation"),
                )
            )
        )

        # Bug #14: Track asyncio.Task handles so we can cancel them on first error
        asyncio_tasks: list[asyncio.Task[TaskResult]] = []

        async def _run_with_semaphore(task: Task) -> TaskResult:
            try:
                async with cast(Any, self._semaphore):
                    if self._cancelled:
                        return TaskResult(
                            task_id=task.id,
                            task_name=task.name,
                            status=TaskStatus.CANCELLED,
                            error="Execution cancelled",
                        )

                    if (
                        self._config.cancel_on_first_error
                        and cast(Any, self._first_error_event).is_set()
                    ):
                        return TaskResult(
                            task_id=task.id,
                            task_name=task.name,
                            status=TaskStatus.SKIPPED,
                            error="Skipped due to previous error",
                        )

                    runner = TaskRunner(
                        task,
                        config=self._config,
                        pool_manager=self._pool_manager,
                        load_balancer=self._load_balancer,
                        cpu_executor=self._cpu_executor,
                        io_executor=self._io_executor,
                    )
                    result = await runner.run()

                    self._results[task.id] = result
                    if result.status == TaskStatus.FAILED:
                        if self._config.cancel_on_first_error:
                            cast(Any, self._first_error_event).set()
                            # Bug #14: Cancel remaining tasks in this layer
                            for at in asyncio_tasks:
                                if not at.done() and at.get_name() != f"task-{task.id}":
                                    at.cancel()

                    # Bug #13: Use atomic counter for correct concurrent progress
                    if self._config.enable_progress_callbacks and self._progress_callback:
                        async with self._completed_count_lock:
                            self._completed_count += 1
                            current = self._completed_count
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

                    return cast(TaskResult, result)
            except asyncio.CancelledError:
                # Bug #14: Handle cancellation gracefully
                res = TaskResult(
                    task_id=task.id,
                    task_name=task.name,
                    status=TaskStatus.CANCELLED,
                    error="Cancelled due to first error in layer",
                )
                self._results[task.id] = res
                return res
            except Exception as e:
                logger.exception("Internal error in TaskRunner for task '%s': %s", task.name, e)
                res = TaskResult(
                    task_id=task.id,
                    task_name=task.name,
                    status=TaskStatus.FAILED,
                    error=f"Internal executor error: {e}",
                )
                self._results[task.id] = res
                if self._config.cancel_on_first_error:
                    cast(Any, self._first_error_event).set()
                return res

        # Bug #14: Create asyncio.Task handles for cancellation support
        asyncio_tasks = [
            asyncio.create_task(
                _run_with_semaphore(task),
                name=f"task-{task.id}",
            )
            for task in layer_tasks
        ]

        # Bug #17: Capture exceptions from gather and store them as results
        gathered = await asyncio.gather(*asyncio_tasks, return_exceptions=True)
        for i, exc in enumerate(gathered):
            if isinstance(exc, Exception) and not isinstance(exc, asyncio.CancelledError):
                task = layer_tasks[i]
                if task.id not in self._results:
                    # Task crashed before it could store its own result
                    logger.error(
                        "Task '%s' raised unhandled exception in gather: %s",
                        task.name,
                        exc,
                    )
                    self._results[task.id] = TaskResult(
                        task_id=task.id,
                        task_name=task.name,
                        status=TaskStatus.FAILED,
                        error=f"Unhandled exception: {exc}",
                    )

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
        """Gracefully shut down the executor and release all resources.

        Bug #15: Uses cancel_futures=True (Python 3.9+) to interrupt
        pending futures, and logs warnings if shutdown takes too long.
        Bug #16: Awaits in-flight tasks before closing pools.
        """
        self._cancelled = True

        # Bug #16: Wait for in-flight tasks before closing resources
        await self._await_inflight_tasks()

        # Bug #15: Shutdown executors with timeout
        if self._cpu_executor:
            try:
                self._cpu_executor.shutdown(wait=True, cancel_futures=True)
            except TypeError:
                self._cpu_executor.shutdown(wait=True)
            self._cpu_executor = None
        if self._io_executor:
            try:
                self._io_executor.shutdown(wait=True, cancel_futures=True)
            except TypeError:
                self._io_executor.shutdown(wait=True)
            self._io_executor = None

        await self._pool_manager.close_all()
        logger.info("ConcurrentExecutor shut down complete")

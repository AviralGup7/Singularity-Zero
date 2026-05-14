"""Task runner extracted from concurrent_executor.

Provides the `_TaskRunner` class which handles execution lifecycle for a
single `Task` (timeouts, retries, resource acquisition, CPU vs IO execution).
This module is intended to keep `concurrent_executor.py` smaller while
preserving the same behavior and API.
"""

import asyncio
import inspect
import logging
import secrets as random
import time
from concurrent.futures.process import BrokenProcessPool
from typing import Any

from src.infrastructure.execution_engine.load_balancer import LoadBalancer
from src.infrastructure.execution_engine.models import (
    ExecutionConfig,
    Task,
    TaskResult,
    TaskStatus,
)
from src.infrastructure.execution_engine.resource_pool import (
    ResourcePool,
    ResourcePoolManager,
)

logger = logging.getLogger(__name__)


class _TaskRunner:
    """Executes a single task with timeout, retry, and resource pool support."""

    def __init__(
        self,
        task: Task,
        config: ExecutionConfig,
        pool_manager: ResourcePoolManager,
        load_balancer: LoadBalancer | None = None,
        cpu_executor: Any | None = None,
        io_executor: Any | None = None,
    ) -> None:
        self._task = task
        self._config = config
        self._pool_manager = pool_manager
        self._load_balancer = load_balancer
        self._cpu_executor = cpu_executor
        self._io_executor = io_executor
        self._worker_id: str | None = None

    async def run(self) -> TaskResult:
        """Execute the task with full lifecycle management.

        Returns:
            TaskResult with the outcome of execution.
        """
        timeout = self._task.timeout_seconds or self._config.default_timeout_seconds
        max_attempts = 1 + self._task.retries
        base_delay = self._task.retry_delay_seconds

        for attempt in range(1, max_attempts + 1):
            result = await self._execute_once(attempt, timeout)

            if result.status in (TaskStatus.SUCCESS, TaskStatus.CANCELLED):
                return result

            if attempt < max_attempts:
                delay = base_delay * (2 ** (attempt - 1))
                jitter = delay * 0.1
                delay_with_jitter = delay + random.uniform(-jitter, jitter)
                logger.info(
                    "Task '%s' (attempt %d/%d) failed: %s. Retrying in %.1fs...",
                    self._task.name,
                    attempt,
                    max_attempts,
                    result.error,
                    delay_with_jitter,
                )
                await asyncio.sleep(delay_with_jitter)

        return result

    async def _execute_once(self, attempt: int, timeout: float) -> TaskResult:
        """Single execution attempt with resource acquisition and timeout."""
        started_at = time.monotonic()

        if self._load_balancer:
            self._worker_id = await self._load_balancer.select_worker(self._task.resource_types)

        acquired_pools: list[ResourcePool] = []
        try:
            acquired_pools = await self._pool_manager.acquire_multi(self._task.resource_types)

            if self._task.cpu_bound:
                result = await self._run_cpu_bound(timeout)
            else:
                result = await self._run_io_bound(timeout)

            finished_at = time.monotonic()
            result.started_at = started_at
            result.finished_at = finished_at
            result.duration_seconds = finished_at - started_at
            result.worker_id = self._worker_id

            if self._load_balancer and self._worker_id:
                self._load_balancer.record_completion(
                    self._worker_id, result.duration_seconds, result.success
                )

            return result

        except TimeoutError:
            finished_at = time.monotonic()
            return TaskResult(
                task_id=self._task.id,
                task_name=self._task.name,
                status=TaskStatus.TIMED_OUT,
                error=f"Timed out after {timeout}s",
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=finished_at - started_at,
                attempts=attempt,
                worker_id=self._worker_id,
            )
        except asyncio.CancelledError:
            finished_at = time.monotonic()
            return TaskResult(
                task_id=self._task.id,
                task_name=self._task.name,
                status=TaskStatus.CANCELLED,
                error="Task was cancelled",
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=finished_at - started_at,
                attempts=attempt,
                worker_id=self._worker_id,
            )
        except Exception as exc:
            finished_at = time.monotonic()
            return TaskResult(
                task_id=self._task.id,
                task_name=self._task.name,
                status=TaskStatus.FAILED,
                error=str(exc),
                exception=exc,
                started_at=started_at,
                finished_at=finished_at,
                duration_seconds=finished_at - started_at,
                attempts=attempt,
                worker_id=self._worker_id,
            )
        finally:
            if acquired_pools:
                await self._pool_manager.release_multi(acquired_pools)

    async def _run_io_bound(self, timeout: float) -> TaskResult:
        """Execute an I/O-bound task with asyncio timeout."""
        fn = self._task.fn
        args = self._task.args
        kwargs = self._task.kwargs

        if inspect.iscoroutinefunction(fn) or (
            callable(fn) and hasattr(fn, "__call__") and inspect.iscoroutinefunction(fn.__call__)
        ):
            coro = fn(*args, **kwargs)
            result = await asyncio.wait_for(coro, timeout=timeout)
        else:
            loop = asyncio.get_running_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: fn(*args, **kwargs)),
                timeout=timeout,
            )

        return TaskResult(
            task_id=self._task.id,
            task_name=self._task.name,
            status=TaskStatus.SUCCESS,
            result=result,
        )

    async def _run_cpu_bound(self, timeout: float) -> TaskResult:
        """Execute a CPU-bound task via shared ProcessPoolExecutor."""
        fn = self._task.fn
        args = self._task.args
        kwargs = self._task.kwargs

        if self._cpu_executor is None:
            return TaskResult(
                task_id=self._task.id,
                task_name=self._task.name,
                status=TaskStatus.FAILED,
                error="No CPU executor available for CPU-bound task",
            )

        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(self._cpu_executor, lambda: fn(*args, **kwargs))
            result = await asyncio.wait_for(future, timeout=timeout)
        except (BrokenProcessPool, TypeError) as exc:
            return TaskResult(
                task_id=self._task.id,
                task_name=self._task.name,
                status=TaskStatus.FAILED,
                error=f"Process execution failed (possibly serialization error): {exc}",
            )

        return TaskResult(
            task_id=self._task.id,
            task_name=self._task.name,
            status=TaskStatus.SUCCESS,
            result=result,
        )

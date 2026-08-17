"""Task runner extracted from concurrent_executor.

Provides the `_TaskRunner` class which handles execution lifecycle for a
single `Task` (timeouts, retries, resource acquisition, CPU vs IO execution).
This module is intended to keep `concurrent_executor.py` smaller while
preserving the same behavior and API.
"""

import asyncio
import inspect
import logging
import random
import threading
import time
from collections.abc import Callable
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

_RETRY_RNG = random.SystemRandom()

# Global tracking of orphan threads for diagnostics
_orphan_threads: dict[str, threading.Thread] = {}
_orphan_lock = threading.Lock()


def _cpu_bound_wrapper(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    """Top-level wrapper for CPU-bound tasks to ensure picklability."""
    return fn(*args, **kwargs)


class _CancellationToken:
    """Thread-safe flag that signals a running function to stop early.

    Functions that support cooperative cancellation should check
    ``token.is_cancelled`` periodically and raise ``CancelledError``
    if set.  For functions that don't check, the caller still knows
    the work is orphaned.
    """

    def __init__(self) -> None:
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()


def _cancellation_aware_wrapper(
    fn: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    token: _CancellationToken,
    task_name: str,
) -> Any:
    """Execute *fn* and track it as an orphan if cancelled before completion.

    If the function doesn't honour the cancellation token, the thread
    continues running but is logged as an orphan so operators can see it.
    """
    thread = threading.current_thread()
    thread_name = getattr(thread, "name", "unknown")
    orphan_key = f"{task_name}:{thread_name}"

    try:
        result = fn(*args, **kwargs)
        if token.is_cancelled:
            # Function completed but after cancellation was requested.
            # The result is stale — discard it but log the orphan.
            logger.warning(
                "Task '%s' completed after timeout (orphan thread %s). Result discarded.",
                task_name,
                thread_name,
            )
            with _orphan_lock:
                _orphan_threads.pop(orphan_key, None)
            raise asyncio.CancelledError()
        with _orphan_lock:
            _orphan_threads.pop(orphan_key, None)
        return result
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.debug("Exception in cancellation-aware wrapper, re-raising", exc_info=True)
        raise


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

        Before each retry, checks system backpressure (concurrency governor
        and resource pool health) to avoid retry storms against saturated
        pools.  If the system is overloaded, retries are either skipped
        (failing immediately) or delayed proportionally.

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
                # Backpressure check: if the system is saturated, don't
                # add more retry load — fail fast or delay longer.
                backpressure_delay = await self._compute_backpressure_delay(base_delay)
                if backpressure_delay is None:
                    logger.warning(
                        "Task '%s' (attempt %d/%d) failed: %s. "
                        "System overloaded — skipping retry, failing immediately.",
                        self._task.name,
                        attempt,
                        max_attempts,
                        result.error,
                    )
                    return result

                delay = base_delay * (2 ** (attempt - 1))
                jitter = delay * 0.1
                delay_with_jitter = delay + _RETRY_RNG.uniform(-jitter, jitter)
                # Apply backpressure multiplier (≥1.0)
                delay_with_jitter *= backpressure_delay
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

    async def _compute_backpressure_delay(self, base_delay: float) -> float | None:
        """Check system backpressure and return a delay multiplier.

        Returns:
            A multiplier >= 1.0 to extend the retry delay, or None if
            the system is too overloaded to retry at all.
        """
        # Check concurrency governor
        try:
            from src.core.concurrency_governor import get_governor

            governor = get_governor()
            snap = governor.snapshot()
            if snap["total_active"] >= snap["global_max"] * 0.9:
                # System is >90% saturated — skip retry
                return None
            if snap["total_active"] >= snap["global_max"] * 0.7:
                # System is >70% saturated — delay longer
                return 2.0
        except ImportError:
            logger.warning("Operation failed in _task_runner.py", exc_info=True)
        try:
            sat = await self._pool_manager.saturation_snapshot()
            max_sat = max(sat.values()) if sat else 0.0
            if max_sat >= 0.95:
                return None
            if max_sat >= 0.80:
                return 1.5
        except Exception:
            logger.warning("Operation failed in _task_runner.py", exc_info=True)
        return 1.0

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
        """Execute an I/O-bound task with asyncio timeout and cancellation tracking.

        For sync functions executed in a thread pool, a cancellation token
        is passed so the wrapper can detect orphaned work.  If the thread
        doesn't honour the token, it is logged as an orphan.
        """
        fn = self._task.fn
        args = self._task.args
        kwargs = self._task.kwargs

        if inspect.iscoroutinefunction(fn) or (
            callable(fn) and hasattr(fn, "__call__") and inspect.iscoroutinefunction(fn.__call__)
        ):
            coro = fn(*args, **kwargs)
            result = await asyncio.wait_for(coro, timeout=timeout)
        else:
            token = _CancellationToken()
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(
                None,
                _cancellation_aware_wrapper,
                fn,
                args,
                kwargs,
                token,
                self._task.name,
            )
            try:
                result = await asyncio.wait_for(future, timeout=timeout)
            except (TimeoutError, asyncio.CancelledError):
                # Signal the thread to stop (cooperative — best effort)
                token.cancel()
                thread_key_prefix = f"{self._task.name}:"
                with _orphan_lock:
                    orphan_keys = [k for k in _orphan_threads if k.startswith(thread_key_prefix)]
                    for k in orphan_keys:
                        logger.warning(
                            "Orphan thread detected after timeout: task '%s', thread %s. "
                            "Thread may still be running — cannot forcibly kill.",
                            self._task.name,
                            k,
                        )
                raise

        return TaskResult(
            task_id=self._task.id,
            task_name=self._task.name,
            status=TaskStatus.SUCCESS,
            result=result,
        )

    async def _run_cpu_bound(self, timeout: float) -> TaskResult:
        """Execute a CPU-bound task via shared ProcessPoolExecutor.

        On timeout, cancels the future and attempts to terminate the worker
        process to prevent CPU pool saturation from orphan work.
        """
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
        future = loop.run_in_executor(self._cpu_executor, _cpu_bound_wrapper, fn, args, kwargs)
        try:
            result = await asyncio.wait_for(future, timeout=timeout)
        except (TimeoutError, asyncio.CancelledError):
            # Cancel the future — this requests cancellation but doesn't
            # kill the worker process.  Attempt to terminate via executor
            # shutdown if it's a ProcessPoolExecutor.
            future.cancel()
            try:
                # ProcessPoolExecutor._processes contains the worker processes
                if hasattr(self._cpu_executor, "_processes"):
                    for pid, proc in self._cpu_executor._processes.items():
                        if proc.is_alive():
                            logger.warning(
                                "CPU task '%s' timed out — terminating worker process pid=%d",
                                self._task.name,
                                pid,
                            )
                            proc.terminate()
            except Exception as exc:
                logger.debug(
                    "Could not terminate CPU worker for task '%s': %s",
                    self._task.name,
                    exc,
                )
            raise
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

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class TaskGroup:
    """Structured concurrency task group with automatic error handling and cleanup."""

    name: str
    _tasks: set[asyncio.Task] = field(default_factory=set)
    _cancelled: bool = False
    _exception: BaseException | None = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def spawn(self, coro: Any, name: str | None = None) -> asyncio.Task:
        """Spawn a task in this group."""
        if self._cancelled:
            raise RuntimeError(f"Task group {self.name} is cancelled")

        task = asyncio.create_task(coro, name=name or coro.__name__)
        self._tasks.add(task)

        def _done(t: asyncio.Task):
            self._tasks.discard(t)
            if t.cancelled():
                return
            if (exc := t.exception()) and not self._exception:
                self._exception = exc
                # Cancel all other tasks on first exception
                for other in self._tasks:
                    if not other.done():
                        other.cancel()

        task.add_done_callback(_done)
        return task

    async def wait_all(self) -> list[Any]:
        """Wait for all tasks to complete. Raises first exception if any."""
        while self._tasks:
            done, pending = await asyncio.wait(
                self._tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                self._tasks.discard(task)
                if task.cancelled():
                    continue
                if exc := task.exception():
                    # Cancel remaining and raise
                    for t in pending:
                        t.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    raise exc

        if self._exception:
            raise self._exception
        return []

    async def cancel_all(self, reason: str = "cancelled") -> None:
        """Cancel all tasks in the group."""
        async with self._lock:
            self._cancelled = True
            for task in self._tasks:
                if not task.done():
                    task.cancel(reason)
            if self._tasks:
                await asyncio.gather(*self._tasks, return_exceptions=True)

    async def __aenter__(self) -> TaskGroup:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if not self._cancelled and exc_type is None:
            await self.wait_all()
        else:
            await self.cancel_all()


@asynccontextmanager
async def task_group(name: str = "group") -> Any:
    """Context manager for structured task groups."""
    group = TaskGroup(name)
    try:
        yield group
    finally:
        if group._tasks and not all(t.done() for t in group._tasks):
            await group.cancel_all()


@dataclass
class SemaphorePool:
    """Bounded semaphore pool with metrics."""
    max_concurrent: int
    _semaphore: asyncio.Semaphore = field(init=False)
    _active: int = field(default=0, init=False)
    _total_acquired: int = field(default=0, init=False)
    _total_released: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

    @asynccontextmanager
    async def acquire(self):
        async with self._lock:
            self._active += 1
            self._total_acquired += 1
        try:
            await self._semaphore.acquire()
            yield
        finally:
            self._semaphore.release()
            async with self._lock:
                self._active -= 1
                self._total_released += 1

    @property
    def active(self) -> int:
        return self._active

    @property
    def available(self) -> int:
        return self.max_concurrent - self._active

    def stats(self) -> dict:
        return {
            "max_concurrent": self.max_concurrent,
            "active": self._active,
            "available": self.available,
            "total_acquired": self._total_acquired,
            "total_released": self._total_released,
        }


@dataclass
class RateLimiter:
    """Token bucket rate limiter."""
    rate_per_second: float
    burst: int = 1
    _tokens: float = field(init=False)
    _last_update: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def __post_init__(self):
        self._tokens = float(self.burst)
        self._last_update = time.monotonic()

    async def acquire(self, tokens: int = 1) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_update
                self._tokens = min(self.burst, self._tokens + elapsed * self.rate_per_second)
                self._last_update = now

                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return

                # Wait for tokens to replenish
                wait = (tokens - self._tokens) / self.rate_per_second
                wait = min(max(wait, 0.001), 60)  # Cap wait time

        await asyncio.sleep(wait)
        # Retry after waiting
        await self.acquire(tokens)

    def stats(self) -> dict:
        return {
            "rate_per_second": self.rate_per_second,
            "burst": self.burst,
            "available_tokens": self._tokens,
        }


class CircuitBreaker:
    """Circuit breaker for external service calls."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state = "closed"  # closed, open, half-open
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float | None = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        async with self._lock:
            if self._state == "open":
                if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                    self._state = "half-open"
                    self._half_open_calls = 0
                else:
                    raise CircuitBreakerOpenError("Circuit breaker is open")

            if self._state == "half-open" and self._half_open_calls >= self.half_open_max_calls:
                raise CircuitBreakerOpenError("Circuit breaker half-open limit reached")

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception:
            await self._on_failure()
            raise

    async def _on_success(self):
        async with self._lock:
            self._failure_count = 0
            if self._state == "half-open":
                self._success_count += 1
                if self._success_count >= self.half_open_max_calls:
                    self._state = "closed"
                    self._success_count = 0

    async def _on_failure(self):
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == "half-open":
                self._state = "open"
            elif self._failure_count >= self.failure_threshold:
                self._state = "open"

    def stats(self) -> dict:
        return {
            "state": self._state,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
        }


class CircuitBreakerOpenError(Exception):
    pass


class TimeoutManager:
    """Manages timeouts with cascading cancellation."""

    def __init__(self, default_timeout: float = 30.0):
        self.default_timeout = default_timeout
        self._active_timeouts: dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def timeout(self, name: str, seconds: float | None = None):
        timeout_sec = seconds or self.default_timeout
        task = asyncio.current_task()
        if not task:
            yield
            return

        timer_task = asyncio.create_task(self._timer(name, timeout_sec, task))
        async with self._lock:
            self._active_timeouts[name] = timer_task

        try:
            yield
        finally:
            timer_task.cancel()
            try:
                await timer_task
            except asyncio.CancelledError:
                pass
            async with self._lock:
                self._active_timeouts.pop(name, None)

    async def _timer(self, name: str, seconds: float, target: asyncio.Task):
        await asyncio.sleep(seconds)
        if not target.done():
            target.cancel(f"Timeout {name} exceeded ({seconds}s)")

    def cancel_all(self) -> None:
        for task in self._active_timeouts.values():
            task.cancel()
        self._active_timeouts.clear()


# Retry policy with exponential backoff
@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: float = 0.1
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,)

    def get_delay(self, attempt: int) -> float:
        import random
        delay = min(self.base_delay * (self.exponential_base ** attempt), self.max_delay)
        jitter_range = delay * self.jitter
        return delay + random.uniform(-jitter_range, jitter_range)

    async def execute(self, func: Callable[..., T], *args, **kwargs) -> T:
        last_exception = None
        for attempt in range(self.max_attempts):
            try:
                return await func(*args, **kwargs)
            except self.retryable_exceptions as e:
                last_exception = e
                if attempt < self.max_attempts - 1:
                    delay = self.get_delay(attempt)
                    logger.warning("Attempt %d/%d failed: %s. Retrying in %.2fs",
                                 attempt + 1, self.max_attempts, e, delay)
                    await asyncio.sleep(delay)
        raise last_exception

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, TypeVar
from uuid import uuid4

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class TransactionManager:
    """Manages database transactions with automatic rollback on error."""

    _connections: dict[str, Any] = field(default_factory=dict)
    _active_transactions: dict[str, Any] = field(default_factory=dict)

    @asynccontextmanager
    async def transaction(self, connection_name: str = "default") -> AsyncIterator[Any]:
        """Start a new transaction."""
        conn = self._connections.get(connection_name)
        if not conn:
            raise RuntimeError(f"No connection registered: {connection_name}")

        tx = await conn.begin()
        tx_id = uuid4().hex
        self._active_transactions[tx_id] = tx

        try:
            yield tx
            await tx.commit()
        except Exception:
            await tx.rollback()
            raise
        finally:
            self._active_transactions.pop(tx_id, None)

    def register_connection(self, name: str, connection: Any) -> None:
        self._connections[name] = connection

    async def close_all(self) -> None:
        for tx in self._active_transactions.values():
            try:
                await tx.rollback()
            except Exception:
                pass
        self._active_transactions.clear()


class UnitOfWork:
    """Unit of Work pattern for managing related operations atomically."""

    def __init__(self, transaction_manager: TransactionManager):
        self._tx_manager = transaction_manager
        self._operations: list[callable] = []
        self._committed = False
        self._rolled_back = False

    def add_operation(self, operation: callable, *args, **kwargs) -> None:
        """Register an operation to be executed within the transaction."""
        self._operations.append((operation, args, kwargs))

    async def commit(self) -> None:
        """Execute all registered operations and commit."""
        if self._committed or self._rolled_back:
            raise RuntimeError("Unit of work already completed")

        for operation, args, kwargs in self._operations:
            await operation(*args, **kwargs)
        self._committed = True

    async def rollback(self) -> None:
        """Rollback any changes."""
        self._rolled_back = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            await self.rollback()
        else:
            await self.commit()


# --- Retry policies ---

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum


class RetryStrategy(Enum):
    FIXED = "fixed"
    EXPONENTIAL = "exponential"
    LINEAR = "linear"


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    retryable_exceptions: tuple[type[Exception], ...] = (Exception,)
    should_retry: Callable[[Exception], bool] | None = None

    def calculate_delay(self, attempt: int) -> float:
        if self.strategy == RetryStrategy.FIXED:
            return self.base_delay
        elif self.strategy == RetryStrategy.EXPONENTIAL:
            return min(self.base_delay * (2 ** (attempt - 1)), self.max_delay)
        elif self.strategy == RetryStrategy.LINEAR:
            return min(self.base_delay * attempt, self.max_delay)
        return self.base_delay


async def retry_async(func: callable, *args, policy: RetryPolicy = None, **kwargs) -> Any:
    """Execute function with retry policy."""
    policy = policy or RetryPolicy()
    last_exception = None

    for attempt in range(1, policy.max_attempts + 1):
        try:
            return await func(*args, **kwargs)
        except policy.retryable_exceptions as e:
            last_exception = e
            if policy.should_retry and not policy.should_retry(e):
                raise
            if attempt == policy.max_attempts:
                raise
            delay = policy.calculate_delay(attempt)
            logging.getLogger(__name__).warning(
                f"Attempt {attempt}/{policy.max_attempts} failed: {e}. Retrying in {delay:.1f}s"
            )
            await asyncio.sleep(delay)

    raise last_exception


# --- Circuit Breaker ---

from enum import Enum


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    success_threshold: int = 2
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _success_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_time >= self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
        return self._state

    async def call(self, func: callable, *args, **kwargs) -> Any:
        if self.state == CircuitState.OPEN:
            raise CircuitBreakerOpenError("Circuit breaker is open")

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except Exception:
            await self._on_failure()
            raise

    async def _on_success(self) -> None:
        async with self._lock:
            self._failure_count = 0
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._success_count = 0

    async def _on_failure(self) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN


class CircuitBreakerOpenError(Exception):
    pass


# --- Resource Pool ---


@dataclass
class ResourcePool:
    """Generic resource pool with health checks."""

    factory: Callable[[], Awaitable[T]]
    max_size: int = 10
    min_size: int = 2
    health_check: Callable[[T], Awaitable[bool]] | None = None
    _pool: asyncio.Queue = field(default_factory=lambda: asyncio.Queue())
    _created: int = field(default=0, init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def initialize(self) -> None:
        for _ in range(self.min_size):
            resource = await self.factory()
            await self._pool.put(resource)
            self._created += 1

    async def acquire(self) -> T:
        async with self._lock:
            if self._pool.empty() and self._created < self.max_size:
                resource = await self.factory()
                self._created += 1
                return resource
            elif not self._pool.empty():
                return self._pool.get_nowait()
            else:
                # Wait for available resource
                return await self._pool.get()

    async def release(self, resource: T) -> None:
        if self.health_check and not await self.health_check(resource):
            # Resource unhealthy, create new one if under max
            if self._created < self.max_size:
                # The replacement was created and then DROPPED: `_created`
                # was incremented for a resource that never entered the pool,
                # so the accounting drifted up by one on every unhealthy
                # release until the pool believed it was full and starved.
                new_resource = await self.factory()
                async with self._lock:
                    self._created += 1
                await self._pool.put(new_resource)
                return
            else:
                # At max, just drop the unhealthy resource
                return
        await self._pool.put(resource)

    async def close(self) -> None:
        while not self._pool.empty():
            resource = self._pool.get_nowait()
            if hasattr(resource, "close"):
                result = resource.close()
                if inspect.isawaitable(result):
                    await result

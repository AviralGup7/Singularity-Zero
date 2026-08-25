"""Host-Isolated Bulkhead Partitions for Global Resource Protection."""

from __future__ import annotations

import asyncio
import threading
from urllib.parse import urlparse

from src.infrastructure.flow_control.circuit_breaker import CircuitBreaker


class BulkheadPartition:
    """Concurrency bulkhead partition and circuit breaker dedicated to a specific host."""

    def __init__(self, host: str, max_concurrent: int = 10) -> None:
        self.host = host
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.circuit_breaker = CircuitBreaker(name=host)

    async def acquire(self) -> None:
        if not self.circuit_breaker.allow_request():
            raise RuntimeError(f"Circuit breaker OPEN for host: {self.host}")
        await self._semaphore.acquire()

    def release(self, success: bool = True) -> None:
        if success:
            self.circuit_breaker.record_success()
        else:
            self.circuit_breaker.record_failure()
        self._semaphore.release()


class BulkheadPool:
    """Manages per-host bulkhead partitions to prevent single-host scan starvation."""

    def __init__(self, default_max_concurrent: int = 10) -> None:
        self.default_max_concurrent = default_max_concurrent
        self._lock = threading.Lock()
        self._partitions: dict[str, BulkheadPartition] = {}

    def get_partition(self, url_or_host: str) -> BulkheadPartition:
        if "://" in url_or_host:
            host = urlparse(url_or_host).netloc or url_or_host
        else:
            host = url_or_host

        with self._lock:
            if host not in self._partitions:
                self._partitions[host] = BulkheadPartition(host, self.default_max_concurrent)
            return self._partitions[host]


__all__ = [
    "BulkheadPartition",
    "BulkheadPool",
]

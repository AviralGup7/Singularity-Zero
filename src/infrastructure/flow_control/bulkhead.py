"""Canonical Endpoint-Isolated Bulkhead Partitions for Global Resource Protection."""

from __future__ import annotations

import asyncio
import threading
from urllib.parse import urlparse

from src.resilience.circuit_breaker import CircuitBreaker


def canonical_isolation_key(url_or_target: str) -> str:
    """Derive canonical (scheme, host, port) endpoint isolation key.

    Unifies bulkhead concurrency limits, circuit breakers, and rate limiters onto
    the same failure domain:
    - http://api.example.com/v1 -> "http://api.example.com:80"
    - https://api.example.com:8443/test -> "https://api.example.com:8443"
    - "192.168.1.10:8080" -> "http://192.168.1.10:8080"
    - "example.com" -> "https://example.com:443"
    """
    raw = str(url_or_target).strip()
    if not raw:
        return "https://unknown:443"

    if "://" not in raw:
        # Default scheme based on port or https
        if ":80" in raw and not raw.endswith(":8080"):
            raw = f"http://{raw}"
        else:
            raw = f"https://{raw}"

    parsed = urlparse(raw)
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    hostname = (parsed.hostname or "localhost").lower()

    if parsed.port:
        port = parsed.port
    elif scheme == "http":
        port = 80
    elif scheme == "https":
        port = 443
    else:
        port = 443

    return f"{scheme}://{hostname}:{port}"


class BulkheadPartition:
    """Concurrency bulkhead partition and circuit breaker dedicated to a unified canonical endpoint."""

    def __init__(self, endpoint_key: str, max_concurrent: int = 10) -> None:
        self.endpoint_key = canonical_isolation_key(endpoint_key)
        self.host = self.endpoint_key  # Backward-compatible property alias
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.circuit_breaker = CircuitBreaker(name=self.endpoint_key)

    async def acquire(self) -> None:
        if not self.circuit_breaker.allow_request():
            raise RuntimeError(f"Circuit breaker OPEN for endpoint: {self.endpoint_key}")
        await self._semaphore.acquire()

    def release(self, success: bool = True) -> None:
        if success:
            self.circuit_breaker.record_success()
        else:
            self.circuit_breaker.record_failure()
        self._semaphore.release()


class BulkheadPool:
    """Manages per-endpoint bulkhead partitions to prevent endpoint scan starvation."""

    def __init__(self, default_max_concurrent: int = 10) -> None:
        self.default_max_concurrent = default_max_concurrent
        self._lock = threading.Lock()
        self._partitions: dict[str, BulkheadPartition] = {}

    def get_partition(self, url_or_target: str) -> BulkheadPartition:
        endpoint_key = canonical_isolation_key(url_or_target)
        with self._lock:
            if endpoint_key not in self._partitions:
                self._partitions[endpoint_key] = BulkheadPartition(
                    endpoint_key, self.default_max_concurrent
                )
            return self._partitions[endpoint_key]


__all__ = [
    "canonical_isolation_key",
    "BulkheadPartition",
    "BulkheadPool",
]

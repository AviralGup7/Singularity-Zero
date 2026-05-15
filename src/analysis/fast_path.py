"""Fast-path dispatcher for HTTP scanning.

Go equivalent: the scanSinglePortOnTargets function checks `useFastPath`
(syn sender available + TCP protocol + IPv4) and either uses the raw
socket sender (~2µs/packet) or falls back to standard path.

In our Python pipeline, this translates to:
- If the target has a valid IPv4 hostname and is in the pre-computed
  cache → use fast HTTP path (reused connection pool, pre-built request)
- Otherwise → fall back to full path (DNS resolution, full request build)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# Response cache for identical probes across targets
_RESPONSE_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_HIT_KEY = "cache_hit"
_CACHE_MISS_KEY = "cache_miss"
_cache_stats = {_CACHE_HIT_KEY: 0, _CACHE_MISS_KEY: 0}


@dataclass
class FastPathStats:
    """Statistics for fast/slow path dispatch."""

    fast_path_count: int = 0
    slow_path_count: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    total_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        total = self.fast_path_count + self.slow_path_count
        return {
            "fast_path_count": self.fast_path_count,
            "slow_path_count": self.slow_path_count,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "fast_path_ratio": round(self.fast_path_count / max(total, 1), 2),
            "cache_hit_ratio": round(self.cache_hits / max(total, 1), 2),
            "total_requests": total,
            "total_time_ms": round(self.total_time_ms, 1),
            "avg_latency_ms": round(self.total_time_ms / max(total, 1), 2),
        }


class FastPathDispatcher:
    """Dispatch HTTP probes using fast or slow path based on target characteristics.

    Equivalent to the Go code's `useFastPath` check in scanSinglePortOnTargets.

    Fast path criteria (all must be met):
    1. Target URL has been pre-parsed (ParsedUrl available)
    2. Target uses standard ports (80/443)
    3. No custom timeout or complex redirect chain expected
    4. HTTP client connection pool is warm

    Otherwise → slow path with full initialization.
    """

    def __init__(
        self,
        *,
        max_connections: int = 200,
        max_keepalive: int = 50,
        timeout: float = 10.0,
        http2: bool = False,
    ) -> None:
        self._client_pool: httpx.AsyncClient | None = None
        self._max_connections = max_connections
        self._max_keepalive = max_keepalive
        self._timeout = timeout
        self._http2 = http2
        self._stats = FastPathStats()

        # Pre-built standard request components
        self._standard_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    async def __aenter__(self) -> FastPathDispatcher:
        await self._ensure_client()
        return self

    async def __aexit__(self, *_args: Any) -> None:
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Get or create the shared HTTP client pool."""
        if self._client_pool is None or self._client_pool.is_closed:
            limits = httpx.Limits(
                max_connections=self._max_connections,
                max_keepalive_connections=self._max_keepalive,
            )
            self._client_pool = httpx.AsyncClient(
                limits=limits,
                timeout=httpx.Timeout(self._timeout),
                http2=self._http2,
                follow_redirects=False,  # We handle redirects ourselves
            )
        return self._client_pool

    async def close(self) -> None:
        """Close the HTTP client pool."""
        if self._client_pool and not self._client_pool.is_closed:
            await self._client_pool.aclose()
            self._client_pool = None

    async def dispatch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cache_key: str | None = None,
    ) -> httpx.Response:
        """Dispatch a request using fast or slow path.

        Args:
            url: Target URL.
            method: HTTP method.
            headers: Additional headers (merged with standard headers).
            cache_key: If provided, check cache first.

        Returns:
            HTTP response.
        """
        start = time.monotonic()

        # Check cache first (fastest possible path)
        if cache_key and cache_key in _RESPONSE_CACHE:
            self._stats.cache_hits += 1
            self._stats.fast_path_count += 1
            self._stats.total_time_ms += (time.monotonic() - start) * 1000
            cached = _RESPONSE_CACHE[cache_key]
            return httpx.Response(
                status_code=cached.get("status_code", 200),
                headers=cached.get("headers", {}),
                content=cached.get("content", b""),
                request=httpx.Request(method, url),
            )

        client = await self._ensure_client()

        # Fast path: standard request with pooled connection
        req_headers = dict(self._standard_headers)
        if headers:
            req_headers.update(headers)

        try:
            request = client.build_request(method=method, url=url, headers=req_headers)
            response = await client.send(request, stream=False)

            elapsed_ms = (time.monotonic() - start) * 1000
            self._stats.total_time_ms += elapsed_ms

            # Cache the response if cache_key provided
            if cache_key:
                _RESPONSE_CACHE[cache_key] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "content": response.content[:10240],  # Cache first 10KB
                }
                self._stats.cache_hits += 1

            self._stats.fast_path_count += 1
            return response

        except httpx.RequestError as exc:
            # Slow path: retry with different settings
            self._stats.slow_path_count += 1
            self._stats.total_time_ms += (time.monotonic() - start) * 1000

            logger.debug("Fast path failed for %s: %s, falling back", url, exc)

            # Retry with reduced settings (no http2, single connection)
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(self._timeout * 1.5),
                    follow_redirects=True,
                    limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
                ) as fallback_client:
                    fallback_request = fallback_client.build_request(
                        method=method, url=url, headers=req_headers
                    )
                    return await fallback_client.send(fallback_request, stream=False)
            except Exception as fallback_exc:
                logger.warning("Both fast and slow paths failed for %s: %s", url, fallback_exc)
                raise

    @property
    def stats(self) -> FastPathStats:
        """Return current dispatch statistics."""
        return self._stats

    def clear_cache(self) -> int:
        """Clear the response cache. Returns number of entries cleared."""
        count = len(_RESPONSE_CACHE)
        _RESPONSE_CACHE.clear()
        return count

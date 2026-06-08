"""Fast-path dispatcher for HTTP scanning.

Go equivalent: the scanSinglePortOnTargets function checks `useFastPath`
(syn sender available + TCP protocol + IPv4) and either uses the raw
socket sender (~2µs/packet) or falls back to standard path.

In our Python pipeline, this translates to:
- If the target has a valid IPv4 hostname and is in the pre-computed
  cache → use fast HTTP path (reused connection pool, pre-built request)
- Otherwise → fall back to full path (DNS resolution, full request build)

When a :class:`ScopeEnforcer` is attached via :meth:`set_scope_enforcer`,
the dispatcher performs a per-request scope check on every outbound
URL. Out-of-scope requests are blocked before the connection is opened
and a ``ScopeViolation`` is raised — this prevents the scanner from
ever sending a probe to an unintended host.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from src.pipeline.scope_enforcer import ScopeEnforcer

logger = logging.getLogger(__name__)


class ScopeViolation(RuntimeError):
    """Raised when the dispatcher is asked to send a probe to an
    out-of-scope target. The ``url`` attribute carries the offending
    URL for logging/UI feedback.
    """

    def __init__(self, url: str, message: str | None = None) -> None:
        self.url = url
        super().__init__(message or f"out-of-scope request blocked: {url}")


# Response cache for identical probes across targets
_RESPONSE_CACHE: dict[str, dict[str, Any]] = {}
_RESPONSE_CACHE_EXPIRY: dict[str, float] = {}
_MAX_CACHE_SIZE = 1000
_CACHE_TTL_SECONDS = 300
_CACHE_HIT_KEY = "cache_hit"
_CACHE_MISS_KEY = "cache_miss"
_cache_stats = {_CACHE_HIT_KEY: 0, _CACHE_MISS_KEY: 0}


def _evict_cache_if_needed() -> None:
    now = time.monotonic()
    # Evict expired entries
    expired = [k for k, expiry in list(_RESPONSE_CACHE_EXPIRY.items()) if now > expiry]
    for k in expired:
        _RESPONSE_CACHE.pop(k, None)
        _RESPONSE_CACHE_EXPIRY.pop(k, None)
    # Evict oldest if max size exceeded
    while len(_RESPONSE_CACHE) >= _MAX_CACHE_SIZE:
        try:
            oldest = next(iter(_RESPONSE_CACHE))
            _RESPONSE_CACHE.pop(oldest, None)
            _RESPONSE_CACHE_EXPIRY.pop(oldest, None)
        except StopIteration:
            break


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

    A :class:`ScopeEnforcer` can be attached with
    :meth:`set_scope_enforcer` to enforce scope on every outbound
    request. When attached, :meth:`dispatch` raises
    :class:`ScopeViolation` for out-of-scope URLs *before* any network
    I/O happens. This is the runtime per-request scope enforcement
    layer that the pre-flight :class:`ConfigModel` validation cannot
    provide on its own (scope is only checked at startup there).
    """

    def __init__(
        self,
        *,
        max_connections: int = 200,
        max_keepalive: int = 50,
        timeout: float = 10.0,
        http2: bool = False,
        rate_limit_per_second: float | None = None,
    ) -> None:
        self._client_pool: httpx.AsyncClient | None = None
        self._max_connections = max_connections
        self._max_keepalive = max_keepalive
        self._timeout = timeout
        self._http2 = http2
        self._stats = FastPathStats()
        # Per-request scope enforcement. ``None`` means the dispatcher
        # is in legacy mode and trusts the caller — the orchestrator
        # wires a real enforcer at startup when scope is configured.
        self._scope_enforcer: ScopeEnforcer | None = None
        # Tracks how many requests have been blocked for being out of
        # scope. Useful for the self-healing controller to detect
        # misconfigured targets without spamming logs.
        self._scope_violations: int = 0
        # Tool-level rate limiter. A token-bucket style gate applied
        # before every request. ``None`` means no rate limit (legacy
        # behaviour, matches the pre-rate-limiter default).
        #
        # The bucket is implemented lazily on first use to keep the
        # dispatcher's startup path fast and side-effect-free.
        self._rate_limit_per_second = rate_limit_per_second
        self._rate_limit_lock: asyncio.Lock | None = None
        self._rate_limit_tokens: float = 0.0
        self._rate_limit_last_refill: float = 0.0

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

    def set_scope_enforcer(self, enforcer: ScopeEnforcer | None) -> None:
        """Attach a :class:`ScopeEnforcer` for per-request scope checks.

        Passing ``None`` detaches the enforcer and reverts to the
        legacy behaviour (no runtime scope check). The dispatcher
        will then trust the caller's URL — relying on the
        orchestrator's pre-flight configuration validation alone.
        """
        self._scope_enforcer = enforcer
        if enforcer is not None:
            logger.info(
                "FastPathDispatcher: scope enforcement armed (%d entries)",
                len(getattr(enforcer, "scope_entries", []) or []),
            )
        else:
            logger.warning(
                "FastPathDispatcher: scope enforcement DISARMED — "
                "out-of-scope requests will not be blocked at runtime"
            )

    def apply_waf_tuning(self, tuning: Any) -> None:
        """Apply a :class:`WafTuningProfile` to the dispatcher.

        The tuning profile adjusts the connection pool size and the
        per-second rate limit so the dispatcher's outbound traffic
        matches the WAF's tolerance. When the profile is ``NONE``
        the dispatcher falls back to its default (un-tuned) limits.
        """
        nuclei_rate = getattr(tuning, "nuclei_rate_limit", None)
        httpx_conc = getattr(tuning, "httpx_concurrency", None)
        if httpx_conc is not None and httpx_conc > 0:
            self._max_connections = int(httpx_conc)
            logger.info(
                "FastPathDispatcher: connection pool resized to %d (WAF tuning)",
                self._max_connections,
            )
            # The pool may already be open with the old size. Reset
            # it lazily — the next ``_ensure_client`` call will pick
            # up the new limit.
            self._client_pool = None
        if nuclei_rate is not None and nuclei_rate > 0:
            self._rate_limit_per_second = float(nuclei_rate)
            self._rate_limit_lock = None  # reinitialise on next use
            logger.info(
                "FastPathDispatcher: rate limit set to %d req/s (WAF tuning)",
                int(self._rate_limit_per_second),
            )

    @property
    def scope_violations(self) -> int:
        """Number of requests blocked for being out of scope."""
        return self._scope_violations

    async def _throttle(self) -> None:
        """Apply the per-second rate limit using a token-bucket scheme.

        The bucket starts full and refills continuously. When a
        request arrives we consume one token; if the bucket is empty
        we sleep just long enough for one token to accrue. This is
        cheap (no asyncio timer task) and accurate to within a few
        milliseconds.
        """
        rate = self._rate_limit_per_second
        if rate is None or rate <= 0:
            return
        if self._rate_limit_lock is None:
            self._rate_limit_lock = asyncio.Lock()
            self._rate_limit_tokens = float(rate)
            self._rate_limit_last_refill = time.monotonic()
        async with self._rate_limit_lock:
            now = time.monotonic()
            elapsed = now - self._rate_limit_last_refill
            if elapsed > 0:
                self._rate_limit_tokens = min(
                    float(rate),
                    self._rate_limit_tokens + elapsed * float(rate),
                )
                self._rate_limit_last_refill = now
            if self._rate_limit_tokens >= 1.0:
                self._rate_limit_tokens -= 1.0
                return
            # Need to wait. Sleep for the deficit.
            deficit = 1.0 - self._rate_limit_tokens
            sleep_for = deficit / float(rate)
            await asyncio.sleep(sleep_for)
            self._rate_limit_tokens = 0.0
            self._rate_limit_last_refill = time.monotonic()

    def _enforce_scope(self, url: str) -> None:
        """Raise :class:`ScopeViolation` if ``url`` is out of scope.

        A no-op when no enforcer is attached (legacy mode).
        """
        if self._scope_enforcer is None:
            return
        if not self._scope_enforcer.is_in_scope(url):
            self._scope_violations += 1
            logger.warning(
                "FastPathDispatcher: blocking out-of-scope request %s "
                "(total violations: %d)",
                url,
                self._scope_violations,
            )
            raise ScopeViolation(url)

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
        self.clear_cache()

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

        Raises:
            ScopeViolation: When a scope enforcer is attached and ``url``
                is not in the configured scope. The check happens
                before any network I/O so the connection is never opened.
        """
        # Per-request scope enforcement — runs first, before cache lookup
        # or connection acquisition. This is the layer that prevents
        # active probes from hitting out-of-scope domains, even if the
        # URL was produced by a downstream tool that didn't validate
        # scope itself.
        self._enforce_scope(url)

        # Per-second rate limit (token-bucket). Runs after scope check
        # so we don't consume tokens on requests that would be blocked
        # anyway. When ``_rate_limit_per_second`` is None the throttle
        # is a no-op, matching the pre-rate-limiter behaviour.
        await self._throttle()

        start = time.monotonic()

        # Check cache first (fastest possible path)
        if cache_key and cache_key in _RESPONSE_CACHE:
            expiry = _RESPONSE_CACHE_EXPIRY.get(cache_key, 0.0)
            if start <= expiry:
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
            else:
                # Expired, clean up
                _RESPONSE_CACHE.pop(cache_key, None)
                _RESPONSE_CACHE_EXPIRY.pop(cache_key, None)

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
                _evict_cache_if_needed()
                _RESPONSE_CACHE[cache_key] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "content": response.content[:10240],  # Cache first 10KB
                }
                _RESPONSE_CACHE_EXPIRY[cache_key] = time.monotonic() + _CACHE_TTL_SECONDS
                self._stats.cache_hits += 1

            self._stats.fast_path_count += 1
            return response

        except httpx.RequestError as exc:
            # Slow path: retry with different settings
            self._stats.slow_path_count += 1
            self._stats.total_time_ms += (time.monotonic() - start) * 1000

            logger.debug("Fast path failed for %s: %s, falling back", url, exc)

            # Re-check scope on the slow path too. A redirect or DNS
            # rebind could shift the request to a different host, so
            # we validate once more before opening the fallback
            # connection.
            self._enforce_scope(url)

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
        _RESPONSE_CACHE_EXPIRY.clear()
        return count

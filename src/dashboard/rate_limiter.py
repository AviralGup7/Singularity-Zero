"""Rate limiting middleware for the FastAPI dashboard.

Provides a configurable rate limiter with in-memory and Redis backends,
implemented as a Starlette middleware for seamless FastAPI integration.
"""

import asyncio
import hashlib
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, cast

from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class RateLimitMetrics:
    """Tracks recent request counts per endpoint for the security monitor."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._limits: dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def record(self, endpoint: str, limit_per_second: int | None = None) -> None:
        now = time.monotonic()
        async with self._lock:
            bucket = self._hits[endpoint]
            bucket.append(now)
            cutoff = now - 5.0
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if limit_per_second is not None:
                self._limits[endpoint] = limit_per_second

    def snapshot(self) -> list[dict[str, Any]]:
        now = time.monotonic()
        items: list[dict[str, Any]] = []
        for endpoint, bucket in list(self._hits.items()):
            recent = [hit for hit in bucket if hit >= now - 5.0]
            if not recent:
                continue
            items.append(
                {
                    "endpoint": endpoint,
                    "requests_per_second": round(len(recent) / 5.0, 2),
                    "recent_count": len(recent),
                    "limit_per_second": self._limits.get(endpoint),
                }
            )
        items.sort(key=lambda item: item["endpoint"])
        return items


_rate_limit_metrics = RateLimitMetrics()


def get_rate_limit_status() -> list[dict[str, Any]]:
    return _rate_limit_metrics.snapshot()


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting behaviour."""

    window_seconds: float = Field(default=60.0, ge=1.0)
    default_limit: int = Field(default=60, ge=1)
    jobs_limit: int = Field(default=10, ge=1)
    replay_limit: int = Field(default=30, ge=1)
    redis_url: str | None = Field(default=None)
    trusted_proxies: list[str] = Field(default_factory=list)
    api_only: bool = Field(default=True)
    excluded_paths: set[str] = Field(
        default_factory=lambda: {"/api/health", "/api/health/live", "/api/health/ready"},
    )
    excluded_prefixes: set[str] = Field(
        default_factory=lambda: {
            "/assets/",
            "/react/",
            "/reports/",
            "/_launcher/",
            "/ws/",
            "/.well-known/",
            "/favicon",
            "/manifest.json",
            "/sw.js",
            "/icon-192.png",
            "/icon-512.png",
        },
    )
    endpoint_limits: dict[str, int] = Field(default_factory=dict)
    endpoint_prefix_limits: dict[str, int] = Field(default_factory=dict)
    adaptive_enabled: bool = Field(default=True)
    adaptive_min_limit: int = Field(default=1, ge=1)
    adaptive_penalty_factor: float = Field(default=0.5, ge=0.1, le=1.0)
    adaptive_decay_seconds: float = Field(default=300.0, ge=1.0)
    adaptive_max_penalties: int = Field(default=4, ge=1)
    adaptive_status_codes: set[int] = Field(default_factory=lambda: {403, 406, 429, 503})
    adaptive_waf_header_patterns: tuple[str, ...] = Field(
        default=(
            "cloudflare",
            "akamai",
            "imperva",
            "incapsula",
            "mod_security",
            "modsecurity",
            "aws waf",
            "x-sucuri",
            "x-iinfo",
            "x-akamai",
        ),
    )

    def get_limit_for_endpoint(self, endpoint: str) -> int:
        """Return the rate limit for a specific endpoint path."""
        if endpoint in self.endpoint_limits:
            return self.endpoint_limits[endpoint]
        matching_prefixes = [
            prefix for prefix in self.endpoint_prefix_limits if endpoint.startswith(prefix)
        ]
        if matching_prefixes:
            best_prefix = max(matching_prefixes, key=len)
            return self.endpoint_prefix_limits[best_prefix]
        if endpoint == "/api/jobs/start":
            return self.jobs_limit
        if endpoint == "/api/replay":
            return self.replay_limit
        return self.default_limit


@dataclass
class _AdaptiveLimitEntry:
    """Tracks temporary limit reductions and latency metrics for a client-endpoint pair."""

    penalties: int = 0
    last_signal: float = 0.0
    expires_at: float = 0.0
    latency_history: list[float] = field(default_factory=list)
    latency_window_size: int = 10

    def active(self, now: float) -> bool:
        return self.penalties > 0 and now < self.expires_at

    def record_latency(self, latency: float) -> float:
        """Add latency sample and return moving average."""
        self.latency_history.append(latency)
        if len(self.latency_history) > self.latency_window_size:
            self.latency_history.pop(0)
        return sum(self.latency_history) / len(self.latency_history)


class AdaptiveLimitController:
    """Temporarily lowers endpoint limits based on WAF signals and latency spikes."""

    def __init__(self, config: RateLimitConfig) -> None:
        self._config = config
        self._entries: dict[str, _AdaptiveLimitEntry] = {}
        self._lock = asyncio.Lock()
        # Latency threshold: if avg latency > 2s or 3x baseline, trigger penalty
        self._latency_threshold_ms = 2000.0

    @staticmethod
    def _key(client_key: str, endpoint: str) -> str:
        return f"{client_key}:{endpoint}"

    async def effective_limit(
        self,
        client_key: str,
        endpoint: str,
        base_limit: int,
    ) -> tuple[int, int]:
        """Return the current effective limit and active penalty count."""
        if not self._config.adaptive_enabled:
            return base_limit, 0

        now = time.monotonic()
        key = self._key(client_key, endpoint)
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return base_limit, 0

            if not entry.active(now):
                # Penalty expired, but keep entry if we have latency history
                if not entry.latency_history:
                    self._entries.pop(key, None)
                return base_limit, 0

            # Exponential backoff on limit: limit * (factor ^ penalties)
            adjusted = int(base_limit * (self._config.adaptive_penalty_factor**entry.penalties))
            return max(self._config.adaptive_min_limit, adjusted), entry.penalties

    async def record_signal(
        self, client_key: str, endpoint: str, latency_ms: float | None = None
    ) -> int:
        """Record a throttle/WAF signal or latency spike and return the new penalty count."""
        if not self._config.adaptive_enabled:
            return 0

        now = time.monotonic()
        key = self._key(client_key, endpoint)
        async with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = _AdaptiveLimitEntry()
                self._entries[key] = entry

            should_penalize = False
            if latency_ms is not None:
                avg_latency = entry.record_latency(latency_ms)
                if avg_latency > self._latency_threshold_ms:
                    logger.warning(
                        "Proactive throttle: latency spike detected for %s (avg=%.1fms)",
                        key,
                        avg_latency,
                    )
                    should_penalize = True
            else:
                # Explicit signal (e.g. 429 status)
                should_penalize = True

            if should_penalize:
                entry.penalties = min(self._config.adaptive_max_penalties, entry.penalties + 1)
                entry.last_signal = now
                entry.expires_at = now + self._config.adaptive_decay_seconds

            return entry.penalties

    async def reset(self, client_key: str | None = None) -> int:
        """Reset adaptive penalties. Returns number of entries removed."""
        async with self._lock:
            if client_key is None:
                count = len(self._entries)
                self._entries.clear()
                return count
            prefix = f"{client_key}:"
            keys = [key for key in self._entries if key.startswith(prefix)]
            for key in keys:
                del self._entries[key]
            return len(keys)


@dataclass
class _WindowEntry:
    """Tracks request timestamps for a single client-endpoint pair."""

    timestamps: list[float] = field(default_factory=list)

    def prune(self, window_seconds: float, now: float) -> None:
        cutoff = now - window_seconds
        lo, hi = 0, len(self.timestamps)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.timestamps[mid] < cutoff:
                lo = mid + 1
            else:
                hi = mid
        if lo > 0:
            self.timestamps = self.timestamps[lo:]

    def count(self, window_seconds: float, now: float) -> int:
        self.prune(window_seconds, now)
        return len(self.timestamps)

    def record(self, now: float) -> None:
        self.timestamps.append(now)

    def retry_after(self, window_seconds: float, now: float) -> int:
        if not self.timestamps:
            return 1
        return max(1, int(window_seconds - (now - self.timestamps[0])) + 1)


class InMemoryRateLimiter:
    """Thread-safe sliding window rate limiter using in-memory storage."""

    def __init__(self, config: RateLimitConfig) -> None:
        self._config = config
        self._buckets: dict[str, _WindowEntry] = defaultdict(_WindowEntry)
        self._lock = asyncio.Lock()

    async def check(
        self,
        client_key: str,
        endpoint: str,
        limit_override: int | None = None,
    ) -> tuple[bool, int, int | None]:
        """Check whether a request is allowed and record it if so."""
        now = time.monotonic()
        limit = limit_override or self._config.get_limit_for_endpoint(endpoint)
        key = f"{client_key}:{endpoint}"

        async with self._lock:
            bucket = self._buckets[key]
            count = bucket.count(self._config.window_seconds, now)

            if count >= limit:
                return False, 0, bucket.retry_after(self._config.window_seconds, now)

            bucket.record(now)
            return True, limit - (count + 1), None


class RedisRateLimiter:
    """Distributed rate limiter using Redis."""

    def __init__(self, config: RateLimitConfig) -> None:
        self._config = config
        import redis

        self._redis = redis.from_url(cast(str, config.redis_url), decode_responses=True)

    async def check(
        self,
        client_key: str,
        endpoint: str,
        limit_override: int | None = None,
    ) -> tuple[bool, int, int | None]:
        """Check whether a request is allowed using Redis-based sliding window."""
        now = time.time()
        limit = limit_override or self._config.get_limit_for_endpoint(endpoint)
        key = f"rate_limit:{client_key}:{endpoint}"
        window = self._config.window_seconds

        try:
            # Use Redis Sorted Set for sliding window
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(key, 0, now - window)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, int(window) + 1)
            results = pipe.execute()

            count = results[1]
            if count >= limit:
                # Get the oldest timestamp to compute retry_after
                oldest = cast(
                    list[tuple[Any, float]], self._redis.zrange(key, 0, 0, withscores=True)
                )
                retry_after = 1
                if oldest:
                    retry_after = max(1, int(window - (now - oldest[0][1])) + 1)
                return False, 0, retry_after

            return True, limit - (count + 1), None
        except Exception as exc:
            logger.error("Redis rate limit check failed: %s", exc)
            return True, 999, None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Production-grade rate limiting middleware with adaptive throttling."""

    def __init__(self, app: Any, config: RateLimitConfig):
        super().__init__(app)
        self._config = config
        self._adaptive = AdaptiveLimitController(config)
        self._limiter: Any
        if config.redis_url:
            self._limiter = RedisRateLimiter(config)
        else:
            self._limiter = InMemoryRateLimiter(config)

    def _extract_client_ip(self, request: Request) -> str:
        """Extract the real client IP, respecting trusted proxies."""
        if self._config.trusted_proxies:
            forwarded_for = request.headers.get("x-forwarded-for")
            if forwarded_for:
                ips = [ip.strip() for ip in forwarded_for.split(",")]
                for ip in reversed(ips):
                    if ip not in self._config.trusted_proxies:
                        return ip
        return request.client.host if request.client else "127.0.0.1"

    def _is_adaptive_signal(self, response: Response) -> bool:
        """Detect target throttling/WAF responses."""
        if response.status_code in self._config.adaptive_status_codes:
            return True

        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        server = headers.get("server", "")
        for pattern in self._config.adaptive_waf_header_patterns:
            if pattern in server or any(pattern in k or pattern in v for k, v in headers.items()):
                return True
        return False

    @staticmethod
    def _api_security_enabled() -> bool:
        return os.getenv("ENABLE_API_SECURITY", "false").strip().lower() == "true"

    @staticmethod
    def _security_global_limit() -> int:
        try:
            return max(1, int(os.getenv("RATE_LIMIT_GLOBAL_RPS", "30")))
        except ValueError:
            return 30

    @staticmethod
    def _is_job_create(path: str, method: str) -> bool:
        return method.upper() == "POST" and path in {"/api/jobs", "/api/jobs/start"}

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        path = request.url.path

        if path in self._config.excluded_paths:
            return await call_next(request)

        if any(path.startswith(prefix) for prefix in self._config.excluded_prefixes):
            return await call_next(request)

        if self._config.api_only and not path.startswith("/api/"):
            return await call_next(request)

        client_ip = self._extract_client_ip(request)
        security_enabled = self._api_security_enabled()

        if security_enabled:
            global_limit = self._security_global_limit()
            await _rate_limit_metrics.record(path, global_limit)
            allowed, remaining, retry_after = await self._limiter.check(
                client_ip,
                "__global__",
                limit_override=global_limit,
            )
            if not allowed:
                store = getattr(request.app.state, "security_store", None)
                if store is not None:
                    store.record_event(
                        "rate_limit_hit",
                        status_code=429,
                        method=request.method,
                        path=path,
                        client_ip=client_ip,
                        detail=f"Global per-IP limit exceeded: {global_limit}/sec",
                    )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate Limit Exceeded",
                        "detail": f"Too many requests. Retry after {retry_after} seconds.",
                        "code": "rate_limit_exceeded",
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(global_limit),
                    },
                )

            if self._is_job_create(path, request.method):
                api_key = request.headers.get("X-API-Key") or request.headers.get(
                    "Authorization", ""
                )
                key_material = api_key if api_key else client_ip
                scoped_key = f"jobs:{hashlib.sha256(key_material.encode('utf-8')).hexdigest()}"
                await _rate_limit_metrics.record("POST /api/jobs", 2)
                allowed, remaining, retry_after = await self._limiter.check(
                    scoped_key,
                    "POST /api/jobs",
                    limit_override=2,
                )
                if not allowed:
                    store = getattr(request.app.state, "security_store", None)
                    if store is not None:
                        store.record_event(
                            "rate_limit_hit",
                            status_code=429,
                            method=request.method,
                            path=path,
                            client_ip=client_ip,
                            detail="Job creation limit exceeded: 2/sec per API key",
                        )
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "Rate Limit Exceeded",
                            "detail": f"Too many job creation requests. Retry after {retry_after} seconds.",
                            "code": "rate_limit_exceeded",
                        },
                        headers={"Retry-After": str(retry_after), "X-RateLimit-Limit": "2"},
                    )

        base_limit = self._config.get_limit_for_endpoint(path)
        await _rate_limit_metrics.record(
            path, base_limit if self._config.window_seconds == 1 else None
        )
        effective_limit, penalty_count = await self._adaptive.effective_limit(
            client_ip,
            path,
            base_limit,
        )
        allowed, remaining, retry_after = await self._limiter.check(
            client_ip,
            path,
            limit_override=effective_limit,
        )

        if not allowed:
            store = getattr(request.app.state, "security_store", None)
            if store is not None and security_enabled:
                store.record_event(
                    "rate_limit_hit",
                    status_code=429,
                    method=request.method,
                    path=path,
                    client_ip=client_ip,
                    detail=f"Endpoint limit exceeded: {effective_limit}",
                )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate Limit Exceeded",
                    "detail": f"Too many requests. Retry after {retry_after} seconds.",
                    "code": "rate_limit_exceeded",
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(effective_limit),
                    "X-RateLimit-Adaptive": str(penalty_count),
                },
            )

        start_time = time.monotonic()
        response = await call_next(request)
        latency_ms = (time.monotonic() - start_time) * 1000.0

        if self._is_adaptive_signal(response):
            penalty_count = await self._adaptive.record_signal(client_ip, path)
        else:
            penalty_count = await self._adaptive.record_signal(
                client_ip, path, latency_ms=latency_ms
            )

        response.headers["X-RateLimit-Limit"] = str(effective_limit)
        response.headers["X-RateLimit-Adaptive"] = str(penalty_count)
        response.headers["X-Response-Latency-Ms"] = f"{latency_ms:.2f}"
        return response


_rate_limiter_instance: Any = None


def get_rate_limiter(config: RateLimitConfig | None = None) -> Any:
    global _rate_limiter_instance
    if _rate_limiter_instance is None:
        cfg = config or RateLimitConfig()
        if cfg.redis_url:
            _rate_limiter_instance = RedisRateLimiter(cfg)
        else:
            _rate_limiter_instance = InMemoryRateLimiter(cfg)
    return _rate_limiter_instance

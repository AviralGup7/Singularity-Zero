"""Advanced rate limiting for the Cyber Security Test Pipeline.

Provides sliding window rate limiting with support for per-IP,
per-user, and per-endpoint limits. Includes distributed rate limiting
via Redis, rate limit headers, and bypass for internal services.

Classes:
    RateLimitResult: Result of a rate limit check
    RateLimiter: Main rate limiter orchestrator

Usage:
    from src.infrastructure.security.rate_limiter import RateLimiter
    from src.infrastructure.security.config import SecurityConfig

    config = SecurityConfig()
    limiter = RateLimiter(config)

    result = limiter.check_rate_limit(
        identifier="192.168.1.1",
        endpoint="/api/jobs",
    )

    if result.is_limited:
        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"},
            headers=result.headers,
        )
"""

import hmac
import os
import threading
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import redis

from pydantic import BaseModel, Field

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.security.config import SecurityConfig

logger = get_pipeline_logger(__name__)


class RateLimitResult(BaseModel):
    """Result of a rate limit check.

    Attributes:
        allowed: Whether the request is allowed.
        limit: Maximum requests allowed in the window.
        remaining: Remaining requests in the current window.
        reset_at: Unix timestamp when the rate limit resets.
        retry_after: Seconds to wait before retrying (0 if allowed).
    """

    allowed: bool = Field(default=True)
    limit: int = Field(default=60)
    remaining: int = Field(default=0)
    reset_at: float = Field(default=0)
    retry_after: float = Field(default=0)

    @property
    def is_limited(self) -> bool:
        """Check if the request is rate limited."""
        return not self.allowed

    @property
    def headers(self) -> dict[str, str]:
        """Generate rate limit response headers.

        Returns:
            Dict with X-RateLimit-* headers.
        """
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
            "X-RateLimit-Reset": str(int(self.reset_at)),
        }
        if not self.allowed:
            headers["Retry-After"] = str(int(self.retry_after))
        return headers


class SlidingWindowCounter:
    """Thread-safe sliding window rate counter.

    Uses a sliding window algorithm with sub-window precision
    for accurate rate limiting without storing individual timestamps.
    """

    def __init__(self, window_seconds: int = 60) -> None:
        """Initialize the sliding window counter.

        Args:
            window_seconds: Window size in seconds.
        """
        self.window_seconds = window_seconds
        self._counters: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def increment(self, key: str, limit: int) -> RateLimitResult:
        """Increment the counter and check against the limit.

        Args:
            key: Unique identifier for the rate limit bucket.
            limit: Maximum requests allowed in the window.

        Returns:
            RateLimitResult with the check outcome.
        """
        now = time.time()

        with self._lock:
            if key not in self._counters:
                self._counters[key] = {
                    "current_window_start": now,
                    "current_count": 0,
                    "previous_count": 0,
                }

            counter = self._counters[key]
            elapsed = now - counter["current_window_start"]

            if elapsed >= self.window_seconds:
                counter["previous_count"] = counter["current_count"]
                counter["current_count"] = 0
                counter["current_window_start"] = now
                elapsed = 0

            window_position = elapsed / self.window_seconds
            estimated_count = (
                counter["previous_count"] * (1 - window_position) + counter["current_count"]
            )

            reset_at = counter["current_window_start"] + self.window_seconds

            if estimated_count >= limit:
                retry_after = reset_at - now
                return RateLimitResult(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    reset_at=reset_at,
                    retry_after=max(0, retry_after),
                )

            counter["current_count"] += 1
            remaining = int(limit - estimated_count - 1)

            return RateLimitResult(
                allowed=True,
                limit=limit,
                remaining=max(0, remaining),
                reset_at=reset_at,
                retry_after=0,
            )

    def cleanup(self, max_age_seconds: float = 3600) -> int:
        """Remove stale counters.

        Args:
            max_age_seconds: Maximum age of counters to keep.

        Returns:
            Number of counters removed.
        """
        now = time.time()
        with self._lock:
            stale_keys = [
                key
                for key, counter in self._counters.items()
                if now - counter["current_window_start"] > max_age_seconds
            ]
            for key in stale_keys:
                del self._counters[key]
            return len(stale_keys)


class RedisSlidingWindowCounter:
    """Distributed sliding window rate counter using Redis.

    Uses Redis sorted sets for accurate distributed rate limiting
    across multiple service instances.
    """

    def __init__(
        self,
        redis_client: redis.Redis[Any] | redis.Redis[bytes],
        window_seconds: int = 60,
        key_prefix: str = "ratelimit",
    ) -> None:
        """Initialize the Redis sliding window counter.

        Args:
            redis_client: Redis client instance.
            window_seconds: Window size in seconds.
            key_prefix: Prefix for Redis keys.
        """
        self.redis_client = redis_client
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix

    def increment(self, key: str, limit: int) -> RateLimitResult:
        """Increment the counter and check against the limit.

        Args:
            key: Unique identifier for the rate limit bucket.
            limit: Maximum requests allowed in the window.

        Returns:
            RateLimitResult with the check outcome.
        """
        now = time.time()
        window_start = now - self.window_seconds
        redis_key = f"{self.key_prefix}:{key}"

        # Use a unique member ID combining timestamp, pid, and random suffix
        # to avoid collisions across distributed instances.
        member_id = f"{now}:{os.getpid()}:{id(self)}"

        pipe = self.redis_client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, window_start)
        pipe.zadd(redis_key, {member_id: now})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, self.window_seconds)
        results = pipe.execute()

        current_count = results[2] if results else 0
        reset_at = now + self.window_seconds

        if current_count > limit:
            return RateLimitResult(
                allowed=False,
                limit=limit,
                remaining=0,
                reset_at=reset_at,
                retry_after=self.window_seconds,
            )

        return RateLimitResult(
            allowed=True,
            limit=limit,
            remaining=max(0, limit - current_count),
            reset_at=reset_at,
            retry_after=0,
        )


class RateLimiter:
    """Main rate limiter orchestrator.

    Supports per-IP, per-user, and per-endpoint rate limits with
    Redis-backed distributed limiting and internal service bypass.

    Attributes:
        config: Security configuration.
        _local_counter: In-memory sliding window counter.
        _redis_counter: Redis-backed counter (if Redis available).
        _endpoint_limits: Per-endpoint rate limit overrides.
        _user_limits: Per-user rate limit overrides.
        _bypass_tokens: Set of tokens that bypass rate limiting.
    """

    def __init__(self, config: SecurityConfig) -> None:
        """Initialize the rate limiter.

        Args:
            config: Security configuration.
        """
        self.config = config
        self._local_counter = SlidingWindowCounter(
            window_seconds=config.rate_limit.window_seconds,
        )
        self._redis_counter: RedisSlidingWindowCounter | None = None
        self._endpoint_limits: dict[str, int] = {
            "/api/jobs": config.rate_limit.jobs_requests_per_minute,
            "/api/replay": config.rate_limit.replay_requests_per_minute,
            "/api/admin": config.rate_limit.admin_requests_per_minute,
        }
        self._user_limits: dict[str, int] = {}
        self._bypass_tokens = set(config.rate_limit.bypass_tokens)
        self._last_cleanup = 0.0

        if config.rate_limit.redis_url:
            self._init_redis_counter()

    def _init_redis_counter(self) -> None:
        """Initialize Redis counter if available."""
        try:
            import redis

            client = redis.Redis.from_url(
                self.config.rate_limit.redis_url,
                decode_responses=True,
            )
            self._redis_counter = RedisSlidingWindowCounter(
                redis_client=client,
                window_seconds=self.config.rate_limit.window_seconds,
            )
        except Exception as exc:
            logger.warning("Redis rate limiter unavailable, using local counters: %s", exc)
            self._redis_counter = None

    def check_rate_limit(
        self,
        identifier: str,
        endpoint: str = "",
        user_id: str | None = None,
        bypass_token: str | None = None,
    ) -> RateLimitResult:
        """Check if a request is within rate limits.

        Rate limits are applied in order:
        1. Bypass token check (if provided, skip rate limiting)
        2. Per-user limit (if user_id provided)
        3. Per-endpoint limit (if endpoint matches)
        4. Default per-IP limit

        Args:
            identifier: Unique identifier (typically IP address).
            endpoint: Request endpoint path.
            user_id: Authenticated user ID (optional).
            bypass_token: Internal service bypass token (optional).

        Returns:
            RateLimitResult with the check outcome.
        """
        if bypass_token and any(hmac.compare_digest(bypass_token, token) for token in self._bypass_tokens):
            return RateLimitResult(
                allowed=True,
                limit=999999,
                remaining=999999,
                reset_at=time.time() + self.config.rate_limit.window_seconds,
            )

        limit = self._get_limit(endpoint, user_id)
        key = self._build_key(identifier, endpoint, user_id)

        now = time.monotonic()
        if now - self._last_cleanup >= 300.0:
            self._local_counter.cleanup(max_age_seconds=self.config.rate_limit.window_seconds * 2)
            self._last_cleanup = now

        if self._redis_counter is not None:
            try:
                return self._redis_counter.increment(key, limit)
            except Exception as exc:
                logger.warning("Redis rate limiter failed, falling back to local counters: %s", exc)

        return self._local_counter.increment(key, limit)

    def set_endpoint_limit(self, endpoint: str, limit: int) -> None:
        """Set a custom rate limit for a specific endpoint.

        Args:
            endpoint: Endpoint path prefix.
            limit: Requests per minute.
        """
        self._endpoint_limits[endpoint] = limit

    def set_user_limit(self, user_id: str, limit: int) -> None:
        """Set a custom rate limit for a specific user.

        Args:
            user_id: User identifier.
            limit: Requests per minute.
        """
        self._user_limits[user_id] = limit

    def add_bypass_token(self, token: str) -> None:
        """Add a token that bypasses rate limiting.

        Args:
            token: Internal service bypass token.
        """
        self._bypass_tokens.add(token)

    def remove_bypass_token(self, token: str) -> bool:
        """Remove a bypass token.

        Args:
            token: Token to remove.

        Returns:
            True if the token was found and removed.
        """
        if token in self._bypass_tokens:
            self._bypass_tokens.discard(token)
            return True
        return False

    def cleanup(self) -> int:
        """Clean up stale rate limit data.

        Returns:
            Number of stale entries removed.
        """
        return self._local_counter.cleanup()

    def _get_limit(self, endpoint: str, user_id: str | None) -> int:
        """Determine the applicable rate limit.

        Args:
            endpoint: Request endpoint path.
            user_id: Authenticated user ID.

        Returns:
            Applicable rate limit.
        """
        if user_id and user_id in self._user_limits:
            return self._user_limits[user_id]

        for prefix, limit in self._endpoint_limits.items():
            # Fix #334: Use exact match or segment-aware matching to avoid matching /api/jobs-admin with /api/jobs
            if endpoint == prefix or endpoint.startswith(prefix + "/"):
                return limit

        return self.config.rate_limit.default_requests_per_minute

    def _build_key(
        self,
        identifier: str,
        endpoint: str,
        user_id: str | None,
    ) -> str:
        """Build a unique rate limit key.

        Args:
            identifier: Unique identifier (IP address).
            endpoint: Request endpoint path.
            user_id: Authenticated user ID.

        Returns:
            Composite rate limit key.
        """
        parts = [identifier]
        if user_id:
            parts.append(f"user:{user_id}")
        if endpoint:
            parts.append(f"endpoint:{endpoint}")
        return ":".join(parts)

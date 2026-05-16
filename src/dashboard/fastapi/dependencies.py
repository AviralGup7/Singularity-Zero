"""FastAPI dependency injection for the dashboard."""

import hmac
import os
from collections.abc import AsyncGenerator
from typing import Any, cast, Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.security import (
    Principal,
    api_security_enabled,
    authenticate_jwt_token,
    raise_for_roles,
)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

_config_instance: DashboardConfig | None = None


def get_config() -> DashboardConfig:
    """Return the dashboard configuration singleton."""
    global _config_instance
    if _config_instance is None:
        _config_instance = DashboardConfig()
    return _config_instance


async def get_db_session(
    config: DashboardConfig = Depends(get_config),
) -> AsyncGenerator[Any]:
    """Provide an async database session for persistence operations.

    Yields a database session object that can be used for async
    database operations. The session is automatically closed after use.
    """
    session = None
    try:
        import aiosqlite

        db_path = config.cache_db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        session = await aiosqlite.connect(db_path)
        session.row_factory = aiosqlite.Row
        yield session
    except ImportError:
        yield None
    finally:
        if session:
            await session.close()


async def get_queue_client(
    request: Request,
) -> Any:
    """Provide the job queue / services client.

    Returns the DashboardServices instance from app state,
    which is initialized during lifespan with persistence.
    """
    return request.app.state.services


async def get_cache_manager(
    request: Request,
) -> Any:
    """Provide the cache manager instance.

    Returns the CacheManager from app state, which is initialized
    during application lifespan with proper configuration.
    """
    return request.app.state.cache_manager


async def require_auth(
    request: Request,
    api_key: str | None = Security(API_KEY_HEADER),
    config: DashboardConfig = Depends(get_config),
) -> dict[str, str]:
    """Validate API key authentication.

    If DASHBOARD_API_KEY is not set, authentication is bypassed.
    Otherwise, the provided API key must match.

    Returns:
        Dict with user info if authenticated.

    Raises:
        HTTPException: If authentication fails.
    """
    if api_security_enabled():
        principal = _security_principal_from_request(request, api_key)
        if principal is None:
            _record_auth_failure(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid X-API-Key or bearer token required",
            )
        return {
            "user": principal.user,
            "role": principal.role,
            "api_key_id": principal.api_key_id or "",
            "auth_method": principal.auth_method,
        }

    configured_key = config.api_key or os.environ.get("DASHBOARD_API_KEY")
    if configured_key is None:
        disabled = os.environ.get("DASHBOARD_AUTH_DISABLED", "true").strip().lower()
        if disabled in ("true", "1", "yes"):
            return {"user": "anonymous", "role": "admin"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: DASHBOARD_API_KEY is not set. Set DASHBOARD_AUTH_DISABLED=true to disable auth in development.",
        )

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide via X-API-Key header or Authorization: Bearer <key>.",
        )

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        api_key = auth_header[7:]

    if not hmac.compare_digest(api_key or "", configured_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    admin_keys = config.admin_keys or [
        k.strip() for k in os.environ.get("DASHBOARD_ADMIN_KEYS", "").split(",") if k.strip()
    ]
    role = "admin" if api_key in admin_keys else "read"

    return {"user": "api_user", "role": role}


def _security_principal_from_request(request: Request, api_key: str | None) -> Principal | None:
    store = getattr(request.app.state, "security_store", None)
    if store is None:
        return None

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return cast(Optional[Principal], authenticate_jwt_token(auth_header[7:]))

    header_key = api_key or request.headers.get("X-API-Key")
    if header_key:
        return cast(Optional[Principal], store.authenticate_key(header_key))
    return None


def _record_auth_failure(request: Request) -> None:
    store = getattr(request.app.state, "security_store", None)
    if store is None:
        return
    store.record_event(
        "invalid_auth",
        status_code=401,
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
        detail="Missing or invalid credentials",
    )


async def require_admin(
    auth: dict[str, str] = Depends(require_auth),
) -> dict[str, str]:
    """Require admin-level authentication.

    Raises:
        HTTPException: If the authenticated user is not an admin.
    """
    if api_security_enabled():
        principal = Principal(
            user=auth.get("user", ""),
            role=auth.get("role", "read_only"),
            api_key_id=auth.get("api_key_id") or None,
            auth_method=auth.get("auth_method", "api_key"),
        )
        raise_for_roles(principal, {"admin"})
        return auth

    if auth.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return auth


async def require_worker(
    auth: dict[str, str] = Depends(require_auth),
) -> dict[str, str]:
    """Require worker-level authentication when API security is enabled."""
    if api_security_enabled():
        principal = Principal(
            user=auth.get("user", ""),
            role=auth.get("role", "read_only"),
            api_key_id=auth.get("api_key_id") or None,
            auth_method=auth.get("auth_method", "api_key"),
        )
        raise_for_roles(principal, {"worker", "admin"})
    return auth


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self) -> None:
        self._buckets: dict[str, list[float]] = {}
        self._window = 60.0

    def check(self, key: str, limit: int) -> tuple[bool, int | None]:
        import time

        now = time.monotonic()
        cutoff = now - self._window

        if key not in self._buckets:
            self._buckets[key] = []

        self._buckets[key] = [t for t in self._buckets[key] if t > cutoff]

        if len(self._buckets[key]) >= limit:
            oldest = self._buckets[key][0]
            retry_after = int(self._window - (now - oldest)) + 1
            return False, max(retry_after, 1)

        self._buckets[key].append(now)
        return True, None


_rate_limiter = RateLimiter()


async def check_rate_limit(
    request: Request,
    config: DashboardConfig = Depends(get_config),
) -> None:
    """Check rate limits per client IP and endpoint.

    Raises:
        HTTPException: If rate limit is exceeded.
    """
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path

    limits = {
        "/api/jobs/start": config.rate_limit_jobs,
        "/api/replay": config.rate_limit_replay,
    }
    limit = limits.get(path, config.rate_limit_default)

    key = f"{client_ip}:{path}"
    allowed, retry_after = _rate_limiter.check(key, limit)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

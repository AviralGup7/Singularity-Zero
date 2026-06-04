"""FastAPI dependency injection for the dashboard."""

import hmac
import logging
import os
from collections.abc import AsyncGenerator
from typing import Any, cast

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from src.core.security import is_sensitive_name
from src.core.tenant_context import TenantContext
from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.security import (
    Principal,
    api_security_enabled,
    authenticate_jwt_token,
    raise_for_roles,
)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

_config_instance: DashboardConfig | None = None
logger = logging.getLogger(__name__)


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
    disabled = os.environ.get("DASHBOARD_AUTH_DISABLED", "false").strip().lower()
    if disabled in ("true", "1", "yes"):
        logger.warning(
            "SECURITY WARNING: Authentication is DISABLED via DASHBOARD_AUTH_DISABLED. "
            "This must NEVER be enabled in production environments!"
        )
        tenant_id = request.headers.get("X-Tenant-ID") or "default"
        TenantContext.set_current_tenant(tenant_id)
        # The disabled bypass now returns the lowest privileged role to avoid
        # giving an unauthenticated client admin-level access. Callers that
        # actually need admin functionality will be rejected by ``require_admin``
        # and must enable real auth.
        return {"user": "anonymous", "role": "read_only", "tenant_id": tenant_id}

    if api_security_enabled():
        principal = _security_principal_from_request(request, api_key)
        if principal is None:
            _record_auth_failure(request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Valid X-API-Key or bearer token required",
            )
        tenant_id = request.headers.get("X-Tenant-ID") or principal.tenant_id or "default"
        TenantContext.set_current_tenant(tenant_id)
        return {
            "user": principal.user,
            "role": principal.role,
            "api_key_id": principal.api_key_id or "",
            "auth_method": principal.auth_method,
            "tenant_id": tenant_id,
        }

    configured_key = config.api_key or os.environ.get("DASHBOARD_API_KEY")
    if configured_key is None:
        # Security Fix: Default DASHBOARD_AUTH_DISABLED to "false" so that
        # authentication is required unless the operator explicitly opts out.
        disabled = os.environ.get("DASHBOARD_AUTH_DISABLED", "false").strip().lower()
        if disabled in ("true", "1", "yes"):
            logger.warning(
                "SECURITY WARNING: Authentication is DISABLED via DASHBOARD_AUTH_DISABLED. "
                "This must NEVER be enabled in production environments!"
            )
            tenant_id = request.headers.get("X-Tenant-ID") or "default"
            TenantContext.set_current_tenant(tenant_id)
            return {"user": "anonymous", "role": "read_only", "tenant_id": tenant_id}
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
    # Bug #27 fix: previously the non-admin role was the literal string
    # ``"read"``, which is not a member of ``ROLE_ORDER`` (the valid
    # values are ``read_only``, ``worker``, ``admin``). When
    # ``api_security_enabled()`` was True, ``raise_for_roles`` would
    # treat the unknown role as rank 0 and refuse every request to
    # endpoints that should accept ``read_only``. Use the canonical
    # ``"read_only"`` string instead.
    role = "admin" if api_key in admin_keys else "read_only"
    tenant_id = request.headers.get("X-Tenant-ID") or "default"
    TenantContext.set_current_tenant(tenant_id)

    return {"user": "api_user", "role": role, "tenant_id": tenant_id}


def _security_principal_from_request(request: Request, api_key: str | None) -> Principal | None:
    store = getattr(request.app.state, "security_store", None)
    if store is None:
        return None

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return cast(Principal | None, authenticate_jwt_token(auth_header[7:]))

    # Security Fix: Tokens in query params can leak into server logs and
    # browser history. Reject them unconditionally — only header-based Bearer auth is allowed.
    leaked = [name for name in request.query_params.keys() if is_sensitive_name(name)]
    if leaked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "Token authentication via query parameters is not allowed. "
                f"Remove parameter(s): {', '.join(sorted(set(leaked)))}. "
                "Use the Authorization: Bearer header instead."
            ),
        )

    header_key = api_key or request.headers.get("X-API-Key")
    if header_key:
        return cast(Principal | None, store.authenticate_key(header_key))
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
    if auth is None:
        # Bug #28 fix: previously the fallback for ``auth is None`` was
        # ``{"user": "anonymous", "role": "admin", ...}`` which silently
        # granted admin role to anonymous requesters when
        # ``api_security_enabled()`` was False. That allowed any
        # unauthenticated caller to reach admin-only handlers. Default
        # to the lowest privilege role and let ``raise_for_roles``
        # below emit the correct 401/403.
        auth = {"user": "anonymous", "role": "read_only", "tenant_id": "default"}
    if api_security_enabled():
        principal = Principal(
            user=auth.get("user", ""),
            role=auth.get("role", "read_only"),
            tenant_id=auth.get("tenant_id", "default"),
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
    if auth is None:
        # Bug #28 fix: same anonymous-default-to-admin privilege
        # escalation as in ``require_admin``. Default to the lowest
        # privilege role and let the role check raise.
        auth = {"user": "anonymous", "role": "read_only", "tenant_id": "default"}
    if api_security_enabled():
        principal = Principal(
            user=auth.get("user", ""),
            role=auth.get("role", "read_only"),
            tenant_id=auth.get("tenant_id", "default"),
            api_key_id=auth.get("api_key_id") or None,
            auth_method=auth.get("auth_method", "api_key"),
        )
        raise_for_roles(principal, {"worker", "admin"})
    return auth


async def get_learning_integration() -> Any:
    """Provide the LearningIntegration singleton (Phase 5.3)."""
    from src.learning.integration import LearningIntegration

    return LearningIntegration.get_or_create()


class RateLimiter:
    """In-memory sliding window rate limiter."""

    def __init__(self) -> None:
        import threading

        self._buckets: dict[str, list[float]] = {}
        self._window = 60.0
        self._lock = threading.Lock()

    def check(self, key: str, limit: int) -> tuple[bool, int | None]:
        import time

        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
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
        # Security Fix: Rate-limit authentication endpoints to prevent brute-force attacks.
        "/api/auth/token": config.rate_limit_auth if hasattr(config, "rate_limit_auth") else 10,
        "/api/auth/login": config.rate_limit_auth if hasattr(config, "rate_limit_auth") else 10,
        "/api/keys": config.rate_limit_auth if hasattr(config, "rate_limit_auth") else 10,
    }

    if path.startswith("/api/remediated/") and path.endswith("/verify"):
        limit = config.rate_limit_remediation
    else:
        limit = limits.get(path, config.rate_limit_default)

    key = f"{client_ip}:{path}"
    allowed, retry_after = _rate_limiter.check(key, limit)

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Retry after {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

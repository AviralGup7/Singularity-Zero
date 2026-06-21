"""FastAPI dependency injection for the dashboard."""

import hmac
import logging
import os
import threading
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
_config_lock = threading.Lock()
logger = logging.getLogger(__name__)

# Cache api_security_enabled() at module load to avoid repeated env var reads
_SECURITY_ENABLED = api_security_enabled()


def get_config() -> DashboardConfig:
    """Return the dashboard configuration singleton."""
    global _config_instance
    if _config_instance is None:
        with _config_lock:
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
    return getattr(request.app.state, "services", None)


async def get_cache_manager(
    request: Request,
) -> Any:
    """Provide the cache manager instance.

    Returns the CacheManager from app state, which is initialized
    during application lifespan with proper configuration.
    """
    return getattr(request.app.state, "cache_manager", None)


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
        # Auth disabled: return operator role so worker endpoints (scan start,
        # restart) function in dev mode. Callers that need admin functionality
        # will be rejected by ``require_admin`` and must enable real auth.
        return {"user": "anonymous", "role": "operator", "tenant_id": tenant_id}

    if _SECURITY_ENABLED:
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
            return {"user": "anonymous", "role": "viewer", "tenant_id": tenant_id}
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
    # values are ``viewer``, ``operator``, ``admin``). When
    # ``api_security_enabled()`` was True, ``raise_for_roles`` would
    # treat the unknown role as rank 0 and refuse every request to
    # endpoints that should accept ``viewer``. Use the canonical
    # ``"viewer"`` string instead.
    role = "admin" if api_key in admin_keys else "viewer"
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
        # No authentication was performed at all. Surface a 401 (not
        # a 403) so the caller knows the request is missing
        # credentials rather than authenticated-but-insufficient. This
        # also lets handler tests assert that body validation
        # (``422``) can win when auth is satisfied - 401 short-
        # circuits before the handler runs but is semantically
        # distinct from 403.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required",
        )
    if _SECURITY_ENABLED:
        principal = Principal(
            user=auth.get("user", ""),
            role=auth.get("role", "viewer"),
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
        # No authentication was performed at all. Surface a 401 (not
        # a 403) so the caller knows the request is missing
        # credentials rather than authenticated-but-insufficient. This
        # mirrors the policy in ``require_admin`` and lets handler
        # tests assert the body-validation (422) contract when auth
        # is otherwise satisfied.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Worker authentication required",
        )
    if _SECURITY_ENABLED:
        principal = Principal(
            user=auth.get("user", ""),
            role=auth.get("role", "viewer"),
            tenant_id=auth.get("tenant_id", "default"),
            api_key_id=auth.get("api_key_id") or None,
            auth_method=auth.get("auth_method", "api_key"),
        )
        raise_for_roles(principal, {"operator", "admin"})
    return auth


async def get_learning_integration() -> Any:
    """Provide the LearningIntegration singleton (Phase 5.3)."""
    from src.learning.integration import LearningIntegration

    return LearningIntegration.get_or_create()


def get_tool_execution_service(request: Request) -> Any:
    """Provide the ToolExecutionService from app state or create a fallback.

    This centralizes the pipeline dependency so individual routers don't
    need to import from ``src.pipeline.services.tool_execution`` directly.
    """
    service = getattr(request.app.state, "tool_execution_service", None)
    if service is not None:
        return service
    try:
        from src.pipeline.services.tool_execution import ToolExecutionService

        return ToolExecutionService()
    except ImportError:
        return None


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

    auth_limit = getattr(config, "rate_limit_auth", 10)
    limits: dict[str, int] = {
        "/api/jobs/start": config.rate_limit_jobs,
        "/api/replay": config.rate_limit_replay,
        "/api/auth/token": auth_limit,
        "/api/auth/login": auth_limit,
        "/api/keys": auth_limit,
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

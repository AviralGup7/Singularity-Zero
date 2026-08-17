"""Infrastructure layer for the Cyber Security Test Pipeline.

Provides caching, execution engine, job queue, observability, security,
and notification services used by the pipeline runtime.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import Any

# ---------------------------------------------------------------------------
# Module self-description
# ---------------------------------------------------------------------------

MODULE_META: dict[str, Any] = {
    "name": "infrastructure",
    "version": "3.1.0",
    "description": (
        "Cross-cutting infrastructure: cache, execution engine, job queue, "
        "observability, security, notifications, scheduling, and frontier/mesh."
    ),
    "layer": "infrastructure",
    "submodules": (
        "cache",
        "checkpoint",
        "db",
        "discovery",
        "execution_engine",
        "frontier",
        "health",
        "mesh",
        "notifications",
        "observability",
        "queue",
        "scheduling",
        "security",
    ),
    "public_api": (
        "cache_manager",
        "job_queue",
        "redis_client",
        "worker",
        "metrics",
        "structured_logging",
        "encryption",
    ),
    "depends_on": ("core",),
    "entry_points": (
        "cyber-worker",
        "cstp-worker",
    ),
    "health_check": "health_check",
}


def health_check() -> dict[str, Any]:
    """Verify infrastructure subsystem health.

    Checks that the cache manager and notification manager are importable.

    Returns:
        Dict with ``status`` (``"ok"`` / ``"degraded"``), ``module``,
        ``version``, and optional ``details`` / ``errors``.
    """
    errors: list[str] = []
    try:
        from src.infrastructure.cache.cache_manager import (  # noqa: F401
            CacheManager,
        )

        cache_ok = True
    except ImportError as exc:
        cache_ok = False
        errors.append(f"CacheManager unavailable: {exc}")
    try:
        from src.infrastructure.notifications.manager import (  # noqa: F401
            NotificationManager,
        )

        notify_ok = True
    except ImportError as exc:
        notify_ok = False
        errors.append(f"NotificationManager unavailable: {exc}")
    status = "ok" if (cache_ok and notify_ok) else "degraded"
    result: dict[str, Any] = {
        "status": status,
        "module": "infrastructure",
        "version": "3.1.0",
        "details": {
            "cache_manager": "available" if cache_ok else "unavailable",
            "notification_manager": "available" if notify_ok else "unavailable",
        },
    }
    if errors:
        result["errors"] = errors
    return result


# ---------------------------------------------------------------------------
# Register self in the global module registry
# ---------------------------------------------------------------------------

from src.core.utils.shared import register_module_meta  # noqa: E402

register_module_meta(MODULE_META)

# ---------------------------------------------------------------------------
# Lazy facade (unchanged)
# ---------------------------------------------------------------------------

_EXPORTS: dict[str, str] = {
    # Cache
    "backends": "src.infrastructure.cache.backends",
    "cache_manager": "src.infrastructure.cache.cache_manager",
    "cache_config": "src.infrastructure.cache.config",
    "invalidation": "src.infrastructure.cache.invalidation",
    "cache_models": "src.infrastructure.cache.models",
    # Execution
    "concurrent_executor": "src.infrastructure.execution_engine.concurrent_executor",
    "load_balancer": "src.infrastructure.execution_engine.load_balancer",
    "resource_pool": "src.infrastructure.execution_engine.resource_pool",
    # Queue
    "job_queue": "src.infrastructure.queue.job_queue",
    "queue_models": "src.infrastructure.queue.models",
    "redis_client": "src.infrastructure.queue.redis_client",
    "worker": "src.infrastructure.queue.worker",
    # Scheduling
    "scheduling": "src.infrastructure.scheduling",
    # Checkpoint
    "checkpoint_module": "src.infrastructure.checkpoint",
    # Config
    "infra_config": "src.infrastructure.config",
    # Observability
    "health_checks": "src.infrastructure.observability.health_checks",
    "metrics": "src.infrastructure.observability.metrics",
    "structured_logging": "src.infrastructure.observability.structured_logging",
    "tracing": "src.infrastructure.observability.tracing",
    # Security
    "auth": "src.infrastructure.security.auth",
    "encryption": "src.infrastructure.security.encryption",
    "headers": "src.infrastructure.security.headers",
    "input_validation": "src.infrastructure.security.input_validation",
    "rate_limiter": "src.infrastructure.security.rate_limiter",
    # Notifications
    "base": "src.infrastructure.notifications.base",
    "email": "src.infrastructure.notifications.email",
    "manager": "src.infrastructure.notifications.manager",
    "slack": "src.infrastructure.notifications.slack",
    "webhook": "src.infrastructure.notifications.webhook",
}

__all__ = [
    # Cache
    "backends",
    "cache_manager",
    "cache_config",
    "invalidation",
    "cache_models",
    # Execution
    "concurrent_executor",
    "load_balancer",
    "resource_pool",
    # Queue
    "job_queue",
    "queue_models",
    "redis_client",
    "worker",
    # Scheduling
    "scheduling",
    # Checkpoint
    "checkpoint_module",
    # Config
    "infra_config",
    # Observability
    "health_checks",
    "metrics",
    "structured_logging",
    "tracing",
    # Security
    "auth",
    "encryption",
    "headers",
    "input_validation",
    "rate_limiter",
    # Notifications
    "base",
    "email",
    "manager",
    "slack",
    "webhook",
]


def __getattr__(name: str) -> ModuleType:
    module_path = _EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(module_path)
    globals()[name] = module
    return module

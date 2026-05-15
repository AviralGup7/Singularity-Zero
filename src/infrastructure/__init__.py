"""Infrastructure layer for the Cyber Security Test Pipeline.

Provides caching, execution engine, job queue, observability, security,
and notification services used by the pipeline runtime.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

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
    "cors": "src.infrastructure.security.cors",
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
    "cors",
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

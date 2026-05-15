"""Queue configuration with defaults and environment variable support.

Provides configuration loading from environment variables with sensible
defaults for development and production environments.
"""

import os
from typing import Any

from src.infrastructure.queue.models import QueueConfig as QueueConfigModel


def load_config(
    override: dict[str, Any] | None = None,
) -> QueueConfigModel:
    """Load queue configuration from environment variables with defaults.

    Environment variables:
        QUEUE_REDIS_URL: Redis connection URL.
        QUEUE_REDIS_DB: Redis database number (0-15).
        QUEUE_REDIS_MAX_CONNECTIONS: Maximum connection pool size.
        QUEUE_NAME: Default queue name.
        QUEUE_DEFAULT_PRIORITY: Default job priority (1-10).
        QUEUE_DEFAULT_MAX_RETRIES: Default max retries per job.
        QUEUE_LEASE_SECONDS: Job claim lease duration in seconds.
        QUEUE_LEASE_CHECK_INTERVAL: Seconds between stale lease checks.
        QUEUE_HEARTBEAT_INTERVAL: Worker heartbeat interval in seconds.
        QUEUE_WORKER_TIMEOUT: Seconds before worker is considered dead.
        QUEUE_DEAD_LETTER_NAME: Dead-letter queue name.
        QUEUE_ENABLE_METRICS: Whether to enable metrics collection.
        QUEUE_METRICS_TTL: Metrics data TTL in seconds.

    Args:
        override: Dict of configuration values to override env vars.

    Returns:
        QueueConfigModel instance with resolved configuration.
    """

    def env_str(key: str, default: str) -> str:
        if override and key.lower() in override:
            return str(override[key.lower()])
        return os.environ.get(f"QUEUE_{key}", default)

    def env_int(key: str, default: int) -> int:
        if override and key.lower() in override:
            return int(override[key.lower()])
        return int(os.environ.get(f"QUEUE_{key}", str(default)))

    def env_float(key: str, default: float) -> float:
        if override and key.lower() in override:
            return float(override[key.lower()])
        return float(os.environ.get(f"QUEUE_{key}", str(default)))

    def env_bool(key: str, default: bool) -> bool:
        if override and key.lower() in override:
            val = override[key.lower()]
            if isinstance(val, bool):
                return val
            return str(val).lower() in ("true", "1", "yes")
        return os.environ.get(f"QUEUE_{key}", str(default)).lower() in ("true", "1", "yes")

    redis_url = env_str("REDIS_URL", "") or None
    redis_db = env_int("REDIS_DB", 0)
    redis_max_connections = env_int("REDIS_MAX_CONNECTIONS", 20)
    queue_name = env_str("NAME", "default")
    default_priority = env_int("DEFAULT_PRIORITY", 5)
    default_max_retries = env_int("DEFAULT_MAX_RETRIES", 3)
    lease_seconds = env_float("LEASE_SECONDS", 300.0)
    lease_check_interval = env_float("LEASE_CHECK_INTERVAL", 60.0)
    heartbeat_interval = env_float("HEARTBEAT_INTERVAL", 15.0)
    worker_timeout = env_float("WORKER_TIMEOUT", 30.0)
    dead_letter_queue_name = env_str("DEAD_LETTER_NAME", "dead_letter")
    enable_metrics = env_bool("ENABLE_METRICS", True)
    metrics_ttl = env_int("METRICS_TTL", 86400)

    return QueueConfigModel(
        redis_url=redis_url,
        redis_db=redis_db,
        redis_max_connections=redis_max_connections,
        queue_name=queue_name,
        default_priority=default_priority,
        default_max_retries=default_max_retries,
        lease_seconds=lease_seconds,
        lease_check_interval=lease_check_interval,
        heartbeat_interval=heartbeat_interval,
        worker_timeout=worker_timeout,
        dead_letter_queue_name=dead_letter_queue_name,
        enable_metrics=enable_metrics,
        metrics_ttl=metrics_ttl,
    )


DEFAULT_CONFIG = load_config()

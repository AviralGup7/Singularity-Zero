"""Configuration module for the concurrent execution engine.

Provides default configuration and utilities for loading configuration
from files or environment overrides.
"""

import os
from pathlib import Path
from typing import Any

import yaml

from src.infrastructure.execution_engine.models import ExecutionConfig, ResourcePool

DEFAULT_EXECUTION_CONFIG = ExecutionConfig(
    max_workers=20,
    max_cpu_workers=4,
    default_timeout_seconds=120.0,
    default_retries=0,
    resource_pools={
        "default": ResourcePool(name="default", max_concurrent=20),
        "network": ResourcePool(name="network", max_concurrent=50),
        "cpu": ResourcePool(name="cpu", max_concurrent=4),
        "external_tools": ResourcePool(name="external_tools", max_concurrent=10),
    },
    enable_load_balancing=True,
    load_balancer_sample_interval_seconds=5.0,
    load_balancer_adjustment_interval_seconds=15.0,
    enable_progress_callbacks=True,
    result_aggregation_mode="all",
    cancel_on_first_error=False,
    shutdown_timeout_seconds=30.0,
)


def load_execution_config(
    config_path: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
) -> ExecutionConfig:
    """Load execution configuration from a YAML file with optional overrides.

    The configuration file should follow this structure:

    .. code-block:: yaml

        max_workers: 20
        max_cpu_workers: 4
        default_timeout_seconds: 120.0
        default_retries: 0
        resource_pools:
          default:
            max_concurrent: 20
          network:
            max_concurrent: 50
        enable_load_balancing: true
        cancel_on_first_error: false

    Args:
        config_path: Path to a YAML configuration file. If None, defaults are used.
        overrides: Dictionary of configuration values to override file/defaults.

    Returns:
        An ExecutionConfig instance with merged configuration.
    """
    config_data: dict[str, Any] = {}

    if config_path is not None:
        path = Path(config_path)
        if path.exists():
            with open(path, encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}
        else:
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

    config_data.update(overrides or {})

    resource_pools_data = config_data.pop("resource_pools", {})
    resource_pools: dict[str, ResourcePool] = {}

    if resource_pools_data:
        for pool_name, pool_config in resource_pools_data.items():
            if isinstance(pool_config, dict):
                resource_pools[pool_name] = ResourcePool(
                    name=pool_name,
                    max_concurrent=pool_config.get("max_concurrent", 10),
                    acquire_timeout_seconds=pool_config.get("acquire_timeout_seconds", 30.0),
                )
            elif isinstance(pool_config, ResourcePool):
                resource_pools[pool_name] = pool_config

    config_data["resource_pools"] = resource_pools

    return ExecutionConfig(**config_data)


def config_from_env() -> ExecutionConfig:
    """Build an ExecutionConfig from environment variables.

    Recognised environment variables:
        EXEC_MAX_WORKERS: Maximum I/O-bound workers.
        EXEC_MAX_CPU_WORKERS: Maximum CPU-bound workers.
        EXEC_DEFAULT_TIMEOUT: Default task timeout in seconds.
        EXEC_DEFAULT_RETRIES: Default retry count.
        EXEC_CANCEL_ON_FIRST_ERROR: "true" to cancel all on first error.
        EXEC_NETWORK_CONCURRENCY: Max concurrent network operations.
        EXEC_EXTERNAL_TOOLS_CONCURRENCY: Max concurrent external tool invocations.

    Returns:
        ExecutionConfig populated from environment variables.
    """
    config = ExecutionConfig()

    if (val := os.environ.get("EXEC_MAX_WORKERS")) is not None:
        config.max_workers = int(val)
    if (val := os.environ.get("EXEC_MAX_CPU_WORKERS")) is not None:
        config.max_cpu_workers = int(val)
    if (val := os.environ.get("EXEC_DEFAULT_TIMEOUT")) is not None:
        config.default_timeout_seconds = float(val)
    if (val := os.environ.get("EXEC_DEFAULT_RETRIES")) is not None:
        config.default_retries = int(val)
    if (val := os.environ.get("EXEC_CANCEL_ON_FIRST_ERROR")) is not None:
        config.cancel_on_first_error = val.lower() in ("true", "1", "yes")
    if (val := os.environ.get("EXEC_NETWORK_CONCURRENCY")) is not None:
        config.resource_pools["network"] = ResourcePool(name="network", max_concurrent=int(val))
    if (val := os.environ.get("EXEC_EXTERNAL_TOOLS_CONCURRENCY")) is not None:
        config.resource_pools["external_tools"] = ResourcePool(
            name="external_tools", max_concurrent=int(val)
        )

    return config

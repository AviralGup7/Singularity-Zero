import asyncio
import unittest
import pytest
from src.infrastructure.execution_engine.concurrent_executor import (
    ConcurrentExecutor,
    ExecutionSummary,
    _DAGScheduler,
)
from src.infrastructure.execution_engine.config import (
    DEFAULT_EXECUTION_CONFIG,
    config_from_env,
    load_execution_config,
)
from src.infrastructure.execution_engine.load_balancer import LoadBalancer, WorkerStats
from src.infrastructure.execution_engine.models import (
    ExecutionConfig,
    ResourcePool,
    Task,
    TaskPriority,
    TaskResult,
    TaskStatus,
)
from src.infrastructure.execution_engine.resource_pool import (
    PoolHealth,
    ResourcePoolManager,
)
from src.infrastructure.execution_engine.resource_pool import (
    ResourcePool as ResourcePoolImpl,
)



class TestExecutionConfig(unittest.TestCase):
    def test_config_defaults(self) -> None:
        config = ExecutionConfig()
        assert config.max_workers == 20
        assert config.max_cpu_workers == 4
        assert config.default_timeout_seconds == 120.0
        assert config.default_retries == 0
        assert config.enable_load_balancing is True
        assert config.cancel_on_first_error is False

    def test_config_resource_pools(self) -> None:
        config = ExecutionConfig()
        assert "default" in config.resource_pools
        assert "network" in config.resource_pools
        assert "cpu" in config.resource_pools
        assert "external_tools" in config.resource_pools
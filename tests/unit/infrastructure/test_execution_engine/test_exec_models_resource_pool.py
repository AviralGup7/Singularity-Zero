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



class TestResourcePoolModel(unittest.TestCase):
    def test_pool_defaults(self) -> None:
        pool = ResourcePool(name="test")
        assert pool.max_concurrent == 10
        assert pool.current_usage == 0
        assert pool.min_size == 1
        assert pool.max_size == 50
        assert pool.acquire_timeout_seconds == 30.0
        assert pool.health_check_interval_seconds == 60.0
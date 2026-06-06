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



class TestPoolHealth(unittest.TestCase):
    def test_health_defaults(self) -> None:
        health = PoolHealth(pool_name="test", max_concurrent=10, current_usage=0, available=10)
        assert health.total_acquisitions == 0
        assert health.total_timeouts == 0
        assert health.total_errors == 0
        assert health.avg_wait_time_seconds == 0.0

    def test_utilisation_pct(self) -> None:
        health = PoolHealth(pool_name="test", max_concurrent=10, current_usage=5, available=5)
        assert health.utilisation_pct == 50.0

    def test_utilisation_zero_max(self) -> None:
        health = PoolHealth(pool_name="test", max_concurrent=0, current_usage=0, available=0)
        assert health.utilisation_pct == 0.0

    def test_is_healthy_no_activity(self) -> None:
        health = PoolHealth(pool_name="test", max_concurrent=10, current_usage=0, available=10)
        assert health.is_healthy is True

    def test_is_healthy_low_timeout_rate(self) -> None:
        health = PoolHealth(
            pool_name="test",
            max_concurrent=10,
            current_usage=0,
            available=10,
            total_acquisitions=90,
            total_timeouts=5,
        )
        assert health.is_healthy is True

    def test_is_unhealthy_high_timeout_rate(self) -> None:
        health = PoolHealth(
            pool_name="test",
            max_concurrent=10,
            current_usage=0,
            available=10,
            total_acquisitions=50,
            total_timeouts=50,
        )
        assert health.is_healthy is False
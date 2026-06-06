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



class TestTaskPriority(unittest.TestCase):
    def test_priority_values(self) -> None:
        assert TaskPriority.CRITICAL.value == 0
        assert TaskPriority.HIGH.value == 1
        assert TaskPriority.NORMAL.value == 2
        assert TaskPriority.LOW.value == 3
        assert TaskPriority.BACKGROUND.value == 4

    def test_priority_ordering(self) -> None:
        assert TaskPriority.CRITICAL < TaskPriority.HIGH
        assert TaskPriority.HIGH < TaskPriority.NORMAL
        assert TaskPriority.LOW < TaskPriority.BACKGROUND
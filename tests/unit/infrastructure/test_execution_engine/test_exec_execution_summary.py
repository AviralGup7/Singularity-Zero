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



class TestExecutionSummary(unittest.TestCase):
    def test_defaults(self) -> None:
        summary = ExecutionSummary()
        assert summary.total_tasks == 0
        assert summary.succeeded == 0
        assert summary.failed == 0
        assert summary.success_rate == 0.0
        assert summary.all_succeeded is True

    def test_success_rate(self) -> None:
        summary = ExecutionSummary(total_tasks=10, succeeded=7, failed=3)
        assert summary.success_rate == 70.0

    def test_all_succeeded_false(self) -> None:
        summary = ExecutionSummary(failed=1)
        assert summary.all_succeeded is False

    def test_all_succeeded_false_cancelled(self) -> None:
        summary = ExecutionSummary(cancelled=1)
        assert summary.all_succeeded is False

    def test_all_succeeded_false_timed_out(self) -> None:
        summary = ExecutionSummary(timed_out=1)
        assert summary.all_succeeded is False
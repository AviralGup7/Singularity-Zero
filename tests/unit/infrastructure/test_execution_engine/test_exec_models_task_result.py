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



class TestTaskResult(unittest.TestCase):
    def test_result_success(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.SUCCESS)
        assert result.success is True
        assert result.failed is False

    def test_result_failed(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.FAILED)
        assert result.success is False
        assert result.failed is True

    def test_result_timed_out(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.TIMED_OUT)
        assert result.success is False
        assert result.failed is True

    def test_result_skipped(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.SKIPPED)
        assert result.success is False
        assert result.failed is False

    def test_result_defaults(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.PENDING)
        assert result.result is None
        assert result.error is None
        assert result.exception is None
        assert result.duration_seconds == 0.0
        assert result.attempts == 1
        assert result.worker_id is None
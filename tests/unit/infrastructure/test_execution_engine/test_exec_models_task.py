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



class TestTask(unittest.TestCase):
    def test_task_defaults(self) -> None:
        def dummy():
            return "ok"

        task = Task(name="test", fn=dummy)
        assert task.id is not None
        assert task.name == "test"
        assert task.priority == TaskPriority.NORMAL
        assert task.dependencies == set()
        assert task.resource_types == ["default"]
        assert task.timeout_seconds == 120.0
        assert task.retries == 0
        assert task.retry_delay_seconds == 1.0
        assert task.tags == []
        assert task.cpu_bound is False
        assert task.metadata == {}
        assert task.args == ()
        assert task.kwargs == {}

    def test_task_custom_values(self) -> None:
        def dummy():
            return "ok"

        task = Task(
            name="custom",
            fn=dummy,
            priority=TaskPriority.HIGH,
            dependencies={"dep1"},
            resource_types=["network"],
            timeout_seconds=60.0,
            retries=3,
            retry_delay_seconds=2.0,
            tags=["tag1"],
            cpu_bound=True,
            metadata={"key": "val"},
        )
        assert task.priority == TaskPriority.HIGH
        assert task.dependencies == {"dep1"}
        assert task.resource_types == ["network"]
        assert task.timeout_seconds == 60.0
        assert task.retries == 3
        assert task.retry_delay_seconds == 2.0
        assert task.tags == ["tag1"]
        assert task.cpu_bound is True
        assert task.metadata == {"key": "val"}

    def test_task_hash(self) -> None:
        def dummy():
            return "ok"

        task = Task(name="test", fn=dummy, id="t1")
        assert hash(task) == hash("t1")
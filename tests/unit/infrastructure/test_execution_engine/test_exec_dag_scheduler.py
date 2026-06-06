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



class TestDAGScheduler(unittest.TestCase):
    def test_no_dependencies(self) -> None:
        def dummy():
            pass

        tasks = [
            Task(name="t1", fn=dummy, id="t1"),
            Task(name="t2", fn=dummy, id="t2"),
        ]
        scheduler = _DAGScheduler(tasks)
        layers = scheduler.get_layers()
        assert len(layers) == 1
        assert len(layers[0]) == 2

    def test_linear_dependencies(self) -> None:
        def dummy():
            pass

        tasks = [
            Task(name="t1", fn=dummy, id="t1"),
            Task(name="t2", fn=dummy, id="t2", dependencies={"t1"}),
            Task(name="t3", fn=dummy, id="t3", dependencies={"t2"}),
        ]
        scheduler = _DAGScheduler(tasks)
        layers = scheduler.get_layers()
        assert len(layers) == 3

    def test_parallel_dependencies(self) -> None:
        def dummy():
            pass

        tasks = [
            Task(name="t1", fn=dummy, id="t1"),
            Task(name="t2", fn=dummy, id="t2", dependencies={"t1"}),
            Task(name="t3", fn=dummy, id="t3", dependencies={"t1"}),
        ]
        scheduler = _DAGScheduler(tasks)
        layers = scheduler.get_layers()
        assert len(layers) == 2
        assert len(layers[1]) == 2

    def test_validate_unknown_dependency(self) -> None:
        def dummy():
            pass

        tasks = [Task(name="t1", fn=dummy, id="t1", dependencies={"unknown"})]
        scheduler = _DAGScheduler(tasks)
        warnings = scheduler.validate()
        assert len(warnings) > 0

    def test_detect_cycle(self) -> None:
        def dummy():
            pass

        tasks = [
            Task(name="t1", fn=dummy, id="t1", dependencies={"t2"}),
            Task(name="t2", fn=dummy, id="t2", dependencies={"t1"}),
        ]
        scheduler = _DAGScheduler(tasks)
        warnings = scheduler.validate()
        assert any("cycle" in w.lower() for w in warnings)
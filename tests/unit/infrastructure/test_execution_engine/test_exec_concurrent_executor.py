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



class TestConcurrentExecutor(unittest.IsolatedAsyncioTestCase):
    @pytest.mark.asyncio
    async def test_executor_defaults(self) -> None:
        executor = ConcurrentExecutor()
        assert executor.pending_count == 0
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_submit_task(self) -> None:
        def dummy():
            return "ok"

        executor = ConcurrentExecutor()
        task = Task(name="test", fn=dummy)
        task_id = executor.submit(task)
        assert task_id == task.id
        assert executor.pending_count == 1
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_submit_many(self) -> None:
        def dummy():
            return "ok"

        executor = ConcurrentExecutor()
        tasks = [Task(name=f"t{i}", fn=dummy) for i in range(3)]
        ids = executor.submit_many(tasks)
        assert len(ids) == 3
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_run_empty(self) -> None:
        executor = ConcurrentExecutor()
        summary = await executor.run()
        assert summary.total_tasks == 0
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_run_single_task(self) -> None:
        def dummy():
            return "done"

        executor = ConcurrentExecutor()
        executor.submit(Task(name="test", fn=dummy))
        summary = await executor.run()
        assert summary.total_tasks == 1
        assert summary.succeeded == 1
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_run_with_dependencies(self) -> None:
        results = []

        def task1_fn():
            results.append("t1")
            return "t1"

        def task2_fn():
            results.append("t2")
            return "t2"

        executor = ConcurrentExecutor()
        t1 = Task(name="t1", fn=task1_fn, id="t1")
        t2 = Task(name="t2", fn=task2_fn, id="t2", dependencies={"t1"})
        executor.submit(t1)
        executor.submit(t2)
        summary = await executor.run()
        assert summary.succeeded == 2
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_cancel_task(self) -> None:
        def dummy():
            return "ok"

        executor = ConcurrentExecutor()
        task = Task(name="test", fn=dummy, id="t1")
        executor.submit(task)
        assert executor.cancel("t1") is True
        assert executor.cancel("nonexistent") is False
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_cancel_all(self) -> None:
        def dummy():
            return "ok"

        executor = ConcurrentExecutor()
        executor.submit(Task(name="t1", fn=dummy, id="t1"))
        executor.submit(Task(name="t2", fn=dummy, id="t2"))
        count = executor.cancel_all()
        assert count == 2
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_progress_callback(self) -> None:
        def dummy():
            return "ok"

        callback_calls = []

        def callback(msg: str, pct: int, meta: dict) -> None:
            callback_calls.append((msg, pct, meta))

        executor = ConcurrentExecutor()
        executor.set_progress_callback(callback)
        executor.submit(Task(name="test", fn=dummy))
        await executor.run()
        assert len(callback_calls) > 0
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_executor_properties(self) -> None:
        executor = ConcurrentExecutor()
        assert isinstance(executor.config, ExecutionConfig)
        assert isinstance(executor.pool_manager, ResourcePoolManager)
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_run_failed_task(self) -> None:
        def failing():
            raise ValueError("test error")

        executor = ConcurrentExecutor()
        executor.submit(Task(name="fail", fn=failing, retries=0))
        summary = await executor.run()
        assert summary.failed == 1
        assert len(summary.errors) == 1
        await executor.shutdown()

    @pytest.mark.asyncio
    async def test_cancel_on_first_error(self) -> None:
        def failing():
            raise ValueError("fail")

        def success():
            return "ok"

        config = ExecutionConfig(cancel_on_first_error=True)
        executor = ConcurrentExecutor(config=config)
        executor.submit(Task(name="fail", fn=failing, id="t1"))
        executor.submit(Task(name="ok", fn=success, id="t2"))
        summary = await executor.run()
        assert summary.failed >= 1
        await executor.shutdown()
"""Unit tests for the concurrent execution engine."""

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


@pytest.mark.unit
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


@pytest.mark.unit
class TestTaskStatus(unittest.TestCase):
    def test_status_values(self) -> None:
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.QUEUED.value == "queued"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.SUCCESS.value == "success"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.CANCELLED.value == "cancelled"
        assert TaskStatus.TIMED_OUT.value == "timed_out"
        assert TaskStatus.SKIPPED.value == "skipped"


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
class TestResourcePoolModel(unittest.TestCase):
    def test_pool_defaults(self) -> None:
        pool = ResourcePool(name="test")
        assert pool.max_concurrent == 10
        assert pool.current_usage == 0
        assert pool.min_size == 1
        assert pool.max_size == 50
        assert pool.acquire_timeout_seconds == 30.0
        assert pool.health_check_interval_seconds == 60.0


@pytest.mark.unit
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


@pytest.mark.unit
class TestExecutionConfigModule(unittest.TestCase):
    def test_default_config_constant(self) -> None:
        assert DEFAULT_EXECUTION_CONFIG.max_workers == 20
        assert DEFAULT_EXECUTION_CONFIG.max_cpu_workers == 4

    def test_config_from_env_defaults(self) -> None:
        config = config_from_env()
        assert isinstance(config, ExecutionConfig)

    def test_load_execution_config_no_path(self) -> None:
        config = load_execution_config()
        assert isinstance(config, ExecutionConfig)

    def test_load_execution_config_with_overrides(self) -> None:
        config = load_execution_config(overrides={"max_workers": 5})
        assert config.max_workers == 5

    def test_load_execution_config_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_execution_config(config_path="/nonexistent/config.yaml")


@pytest.mark.unit
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


@pytest.mark.unit
class TestResourcePoolImpl(unittest.IsolatedAsyncioTestCase):
    @pytest.mark.asyncio
    async def test_pool_creation(self) -> None:
        pool = ResourcePoolImpl(name="test", max_concurrent=5, acquire_timeout=10.0)
        assert pool.name == "test"
        assert pool.max_concurrent == 5
        assert pool.available == 5
        assert pool.current_usage == 0
        await pool.close()

    @pytest.mark.asyncio
    async def test_acquire_release(self) -> None:
        pool = ResourcePoolImpl(name="test", max_concurrent=1)
        await pool.acquire()
        assert pool.current_usage == 1
        await pool.release()
        assert pool.current_usage == 0
        await pool.close()

    @pytest.mark.asyncio
    async def test_acquire_timeout(self) -> None:
        pool = ResourcePoolImpl(name="test", max_concurrent=1, acquire_timeout=0.1)
        await pool.acquire()
        with pytest.raises(asyncio.TimeoutError):
            await pool.acquire(timeout=0.1)
        await pool.release()
        await pool.close()

    @pytest.mark.asyncio
    async def test_acquire_on_closed_pool(self) -> None:
        pool = ResourcePoolImpl(name="test")
        await pool.close()
        with pytest.raises(RuntimeError):
            await pool.acquire()

    @pytest.mark.asyncio
    async def test_resize_increase(self) -> None:
        pool = ResourcePoolImpl(name="test", max_concurrent=2)
        await pool.resize(5)
        assert pool.max_concurrent == 5
        await pool.close()

    @pytest.mark.asyncio
    async def test_resize_invalid(self) -> None:
        pool = ResourcePoolImpl(name="test")
        with pytest.raises(ValueError):
            await pool.resize(0)
        await pool.close()

    @pytest.mark.asyncio
    async def test_health_check(self) -> None:
        pool = ResourcePoolImpl(name="test")
        health = await pool.health_check()
        assert health.pool_name == "test"
        await pool.close()

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        pool = ResourcePoolImpl(name="test", max_concurrent=1)
        async with pool:
            assert pool.current_usage == 1
        assert pool.current_usage == 0
        await pool.close()

    @pytest.mark.asyncio
    async def test_context_manager_error(self) -> None:
        pool = ResourcePoolImpl(name="test", max_concurrent=1)
        try:
            async with pool:
                raise ValueError("test")
        except ValueError:
            pass
        assert pool.current_usage == 0
        assert pool.health.total_errors == 1
        await pool.close()


@pytest.mark.unit
class TestResourcePoolManager(unittest.IsolatedAsyncioTestCase):
    @pytest.mark.asyncio
    async def test_register_and_get_pool(self) -> None:
        manager = ResourcePoolManager()
        pool = ResourcePoolImpl(name="test", max_concurrent=5)
        manager.register_pool(pool)
        assert manager.get_pool("test") is pool
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_get_pool_not_found(self) -> None:
        manager = ResourcePoolManager()
        with pytest.raises(KeyError):
            manager.get_pool("nonexistent")
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_acquire_multi(self) -> None:
        manager = ResourcePoolManager()
        manager.register_pool(ResourcePoolImpl(name="pool1", max_concurrent=5))
        manager.register_pool(ResourcePoolImpl(name="pool2", max_concurrent=5))
        acquired = await manager.acquire_multi(["pool1", "pool2"])
        assert len(acquired) == 2
        await manager.release_multi(acquired)
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_acquire_multi_duplicate(self) -> None:
        manager = ResourcePoolManager()
        manager.register_pool(ResourcePoolImpl(name="pool1", max_concurrent=5))
        acquired = await manager.acquire_multi(["pool1", "pool1"])
        assert len(acquired) == 1
        await manager.release_multi(acquired)
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_health_check_all(self) -> None:
        manager = ResourcePoolManager()
        manager.register_pool(ResourcePoolImpl(name="p1"))
        results = await manager.health_check_all()
        assert "p1" in results
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_dynamic_resize_high_load(self) -> None:
        manager = ResourcePoolManager()
        manager.register_pool(ResourcePoolImpl(name="p1", max_concurrent=10))
        await manager.dynamic_resize("p1", 0.9)
        pool = manager.get_pool("p1")
        assert pool.max_concurrent < 10
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_dynamic_resize_low_load(self) -> None:
        manager = ResourcePoolManager()
        manager.register_pool(ResourcePoolImpl(name="p1", max_concurrent=10))
        await manager.dynamic_resize("p1", 0.1)
        pool = manager.get_pool("p1")
        assert pool.max_concurrent > 10
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_dynamic_resize_medium_load(self) -> None:
        manager = ResourcePoolManager()
        manager.register_pool(ResourcePoolImpl(name="p1", max_concurrent=10))
        await manager.dynamic_resize("p1", 0.5)
        pool = manager.get_pool("p1")
        assert pool.max_concurrent == 10
        await manager.close_all()

    @pytest.mark.asyncio
    async def test_close_all(self) -> None:
        manager = ResourcePoolManager()
        manager.register_pool(ResourcePoolImpl(name="p1"))
        await manager.close_all()
        assert len(manager.pools) == 0


@pytest.mark.unit
class TestWorkerStats(unittest.TestCase):
    def test_defaults(self) -> None:
        stats = WorkerStats(worker_id="w1")
        assert stats.active_tasks == 0
        assert stats.completed_tasks == 0
        assert stats.failed_tasks == 0
        assert stats.backpressure_factor == 1.0

    def test_total_tasks(self) -> None:
        stats = WorkerStats(worker_id="w1", completed_tasks=5, failed_tasks=3)
        assert stats.total_tasks == 8

    def test_is_overloaded(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=11)
        assert stats.is_overloaded is True

    def test_is_not_overloaded(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=5)
        assert stats.is_overloaded is False

    def test_is_idle(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=0, completed_tasks=5)
        assert stats.is_idle is True

    def test_is_not_idle(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=1)
        assert stats.is_idle is False

    def test_record_completion_success(self) -> None:
        stats = WorkerStats(worker_id="w1")
        stats.record_start()
        stats.record_completion(1.5, success=True)
        assert stats.active_tasks == 0
        assert stats.completed_tasks == 1
        assert stats.avg_task_duration_seconds == 1.5

    def test_record_completion_failure(self) -> None:
        stats = WorkerStats(worker_id="w1")
        stats.record_start()
        stats.record_completion(2.0, success=False)
        assert stats.failed_tasks == 1

    def test_compute_backpressure_no_tasks(self) -> None:
        stats = WorkerStats(worker_id="w1")
        bp = stats.compute_backpressure()
        assert bp == 1.0

    def test_compute_backpressure_with_tasks(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=5, completed_tasks=10, failed_tasks=0)
        bp = stats.compute_backpressure()
        assert 0.0 <= bp <= 1.0


@pytest.mark.unit
class TestLoadBalancer(unittest.IsolatedAsyncioTestCase):
    @pytest.mark.asyncio
    async def test_initial_workers(self) -> None:
        lb = LoadBalancer(num_workers=3)
        assert len(lb.worker_stats) == 3

    @pytest.mark.asyncio
    async def test_select_worker(self) -> None:
        lb = LoadBalancer(num_workers=2)
        worker_id = await lb.select_worker()
        assert worker_id in ("worker-0", "worker-1")

    @pytest.mark.asyncio
    async def test_select_worker_no_workers(self) -> None:
        lb = LoadBalancer(num_workers=0)
        with pytest.raises(RuntimeError):
            await lb.select_worker()

    @pytest.mark.asyncio
    async def test_add_worker(self) -> None:
        lb = LoadBalancer(num_workers=1)
        lb.add_worker("custom-worker")
        assert "custom-worker" in lb.worker_stats

    @pytest.mark.asyncio
    async def test_remove_worker(self) -> None:
        lb = LoadBalancer(num_workers=2)
        lb.remove_worker("worker-0")
        assert "worker-0" not in lb.worker_stats

    @pytest.mark.asyncio
    async def test_record_completion(self) -> None:
        lb = LoadBalancer(num_workers=2)
        await lb.select_worker()
        lb.record_completion("worker-0", 1.0, success=True)
        stats = lb.worker_stats["worker-0"]
        assert stats.completed_tasks == 1

    @pytest.mark.asyncio
    async def test_adjust_concurrency(self) -> None:
        lb = LoadBalancer(num_workers=2)
        new_concurrency = await lb.adjust_concurrency()
        assert isinstance(new_concurrency, int)

    @pytest.mark.asyncio
    async def test_get_load_summary(self) -> None:
        lb = LoadBalancer(num_workers=2)
        summary = await lb.get_load_summary()
        assert "workers" in summary
        assert "total_active" in summary
        assert "effective_concurrency" in summary

    @pytest.mark.asyncio
    async def test_reset(self) -> None:
        lb = LoadBalancer(num_workers=2)
        await lb.select_worker()
        lb.reset()
        stats = lb.worker_stats["worker-0"]
        assert stats.active_tasks == 0
        assert lb.effective_concurrency == lb.target_concurrency

    @pytest.mark.asyncio
    async def test_concurrency_properties(self) -> None:
        lb = LoadBalancer(num_workers=4)
        assert lb.effective_concurrency == 4
        assert lb.target_concurrency == 4

    @pytest.mark.asyncio
    async def test_adjust_concurrency_empty(self) -> None:
        lb = LoadBalancer(num_workers=0)
        result = await lb.adjust_concurrency()
        assert result == 0


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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

"""Execution engine benchmarks.

Measures DAG-based task scheduling, concurrency limiting, resource pool
management, and load balancing of the execution_engine package.
"""

import asyncio
import time

import pytest


class TestTaskSubmission:
    """Benchmark task submission operations."""

    def test_submit_single_task(self, concurrent_executor, benchmark):
        """Measure time to submit a single task."""
        from src.infrastructure.execution_engine.models import Task

        def _submit():
            task = Task(
                name="benchmark_task",
                fn=lambda: {"result": "ok"},
                resource_types=["default"],
            )
            return concurrent_executor.submit(task)

        result = benchmark(_submit)
        assert result is not None

    def test_submit_100_tasks(self, concurrent_executor, benchmark):
        """Measure time to submit 100 tasks."""
        from src.infrastructure.execution_engine.models import Task

        def _submit_batch():
            tasks = []
            for i in range(100):
                task = Task(
                    name=f"task_{i}",
                    fn=lambda i=i: {"index": i},
                    resource_types=["default"],
                )
                tasks.append(task)
            return concurrent_executor.submit_many(tasks)

        result = benchmark(_submit_batch)
        assert len(result) == 100

    def test_submit_1000_tasks(self, concurrent_executor, benchmark):
        """Measure time to submit 1000 tasks."""
        from src.infrastructure.execution_engine.models import Task

        def _submit_batch():
            tasks = []
            for i in range(1000):
                task = Task(
                    name=f"task_{i}",
                    fn=lambda i=i: {"index": i},
                    resource_types=["default"],
                )
                tasks.append(task)
            return concurrent_executor.submit_many(tasks)

        result = benchmark(_submit_batch)
        assert len(result) == 1000


class TestTaskExecution:
    """Benchmark task execution performance."""

    def test_execute_single_io_task(self, benchmark):
        """Measure execution time for a single I/O-bound task."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=5)
        executor = ConcurrentExecutor(config)

        def simple_fn():
            return {"result": "ok"}

        task = Task(
            name="io_task",
            fn=simple_fn,
            resource_types=["default"],
        )
        executor.submit(task)

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.succeeded == 1

    def test_execute_10_concurrent_tasks(self, benchmark):
        """Measure execution time for 10 concurrent tasks."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=10)
        executor = ConcurrentExecutor(config)

        def simple_fn(idx):
            return {"index": idx}

        for i in range(10):
            task = Task(
                name=f"task_{i}",
                fn=lambda i=i: simple_fn(i),
                resource_types=["default"],
            )
            executor.submit(task)

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.succeeded == 10

    def test_execute_50_concurrent_tasks(self, benchmark):
        """Measure execution time for 50 concurrent tasks."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=20)
        executor = ConcurrentExecutor(config)

        for i in range(50):
            task = Task(
                name=f"task_{i}",
                fn=lambda i=i: {"index": i},
                resource_types=["default"],
            )
            executor.submit(task)

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.succeeded == 50

    def test_execute_with_dependencies(self, benchmark):
        """Measure execution time with task dependencies."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=10)
        executor = ConcurrentExecutor(config)

        results_log = []

        def task_a():
            results_log.append("a")
            return {"step": "a"}

        def task_b():
            results_log.append("b")
            return {"step": "b"}

        def task_c():
            results_log.append("c")
            return {"step": "c"}

        task1 = Task(name="task_a", fn=task_a, resource_types=["default"])
        task2 = Task(
            name="task_b",
            fn=task_b,
            resource_types=["default"],
            dependencies={task1.id},
        )
        task3 = Task(
            name="task_c",
            fn=task_c,
            resource_types=["default"],
            dependencies={task1.id, task2.id},
        )

        executor.submit(task1)
        executor.submit(task2)
        executor.submit(task3)

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.succeeded == 3
        assert "a" in results_log
        assert "b" in results_log
        assert "c" in results_log

    def test_execute_dag_layers(self, benchmark):
        """Measure execution time for multi-layer DAG."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=10)
        executor = ConcurrentExecutor(config)

        layer_start = time.monotonic()
        layer_times = []

        def make_task(name, deps=None):
            def fn():
                layer_times.append(time.monotonic() - layer_start)
                return {"name": name}

            return Task(
                name=name,
                fn=fn,
                resource_types=["default"],
                dependencies=deps or set(),
            )

        t1 = make_task("t1")
        t2 = make_task("t2")
        t3 = make_task("t3", deps={t1.id})
        t4 = make_task("t4", deps={t2.id})
        t5 = make_task("t5", deps={t3.id, t4.id})

        executor.submit_many([t1, t2, t3, t4, t5])

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.succeeded == 5


class TestResourcePools:
    """Benchmark resource pool management."""

    def test_pool_acquire_release(self, benchmark):
        """Measure resource pool acquire/release latency."""
        from src.infrastructure.execution_engine.resource_pool import (
            ResourcePool,
            ResourcePoolManager,
        )

        async def _acquire_release():
            manager = ResourcePoolManager()
            pool = ResourcePool(name="benchmark", max_concurrent=10)
            manager.register_pool(pool)
            try:
                acquired = await manager.acquire_multi(["benchmark"])
                await manager.release_multi(acquired)
            finally:
                await manager.close_all()

        benchmark(lambda: asyncio.run(_acquire_release()))

    def test_pool_contention(self, benchmark):
        """Measure pool behavior under contention."""
        from src.infrastructure.execution_engine.resource_pool import (
            ResourcePool,
            ResourcePoolManager,
        )

        async def _contention():
            manager = ResourcePoolManager()
            pool = ResourcePool(name="contention", max_concurrent=2)
            manager.register_pool(pool)

            async def worker(idx):
                acquired = await manager.acquire_multi(["contention"])
                await asyncio.sleep(0.01)
                await manager.release_multi(acquired)
                return idx

            try:
                tasks = [worker(i) for i in range(10)]
                return await asyncio.gather(*tasks)
            finally:
                await manager.close_all()

        result = benchmark(lambda: asyncio.run(_contention()))
        assert len(result) == 10


class TestLoadBalancer:
    """Benchmark load balancer performance."""

    def test_worker_selection(self, benchmark):
        """Measure load balancer worker selection latency."""
        from src.infrastructure.execution_engine.load_balancer import LoadBalancer

        lb = LoadBalancer(num_workers=10)
        asyncio.run(lb.start_monitoring())

        async def _select():
            return await lb.select_worker(["default"])

        result = benchmark(lambda: asyncio.run(_select()))
        assert result is not None

        asyncio.run(lb.stop_monitoring())

    def test_completion_recording(self, benchmark):
        """Measure load balancer completion recording latency."""
        from src.infrastructure.execution_engine.load_balancer import LoadBalancer

        lb = LoadBalancer(num_workers=5)

        def _record():
            lb.record_completion("worker_0", 0.5, True)
            lb.record_completion("worker_1", 1.0, False)
            lb.record_completion("worker_2", 0.3, True)

        benchmark(_record)


class TestConcurrentExecutorScaling:
    """Benchmark executor scaling characteristics."""

    @pytest.mark.parametrize("num_tasks", [10, 50, 100])
    def test_scaling_with_task_count(self, benchmark, num_tasks):
        """Measure execution time scaling with task count."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=min(num_tasks, 20))
        executor = ConcurrentExecutor(config)

        for i in range(num_tasks):
            task = Task(
                name=f"scale_{i}",
                fn=lambda i=i: {"index": i},
                resource_types=["default"],
            )
            executor.submit(task)

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.succeeded == num_tasks

    @pytest.mark.parametrize("max_workers", [1, 5, 10, 20])
    def test_scaling_with_worker_count(self, benchmark, max_workers):
        """Measure execution time scaling with worker count."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=max_workers)
        executor = ConcurrentExecutor(config)

        for i in range(20):
            task = Task(
                name=f"worker_test_{i}",
                fn=lambda i=i: {"index": i},
                resource_types=["default"],
            )
            executor.submit(task)

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.succeeded == 20


class TestExecutionCancellation:
    """Benchmark task cancellation performance."""

    def test_cancel_pending_tasks(self, benchmark):
        """Measure time to cancel pending tasks."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        def _cancel_all():
            config = ExecutionConfig(max_workers=1)
            executor = ConcurrentExecutor(config)

            for i in range(50):
                task = Task(
                    name=f"cancel_{i}",
                    fn=lambda i=i: {"index": i},
                    resource_types=["default"],
                )
                executor.submit(task)

            return executor.cancel_all()

        result = benchmark(_cancel_all)
        assert result == 50

    def test_cancel_on_first_error(self, benchmark):
        """Measure cancel-on-first-error behavior."""
        from src.infrastructure.execution_engine.concurrent_executor import ConcurrentExecutor
        from src.infrastructure.execution_engine.models import ExecutionConfig, Task

        config = ExecutionConfig(max_workers=5, cancel_on_first_error=True)
        executor = ConcurrentExecutor(config)

        def failing_fn():
            raise ValueError("intentional failure")

        def success_fn():
            return {"ok": True}

        t1 = Task(name="fail", fn=failing_fn, resource_types=["default"])
        t2 = Task(name="success_1", fn=success_fn, resource_types=["default"])
        t3 = Task(name="success_2", fn=success_fn, resource_types=["default"])

        executor.submit_many([t1, t2, t3])

        async def _run():
            return await executor.run()

        summary = benchmark(lambda: asyncio.run(_run()))
        assert summary.failed >= 1

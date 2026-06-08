import unittest

import pytest

from src.infrastructure.execution_engine.load_balancer import LoadBalancer


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

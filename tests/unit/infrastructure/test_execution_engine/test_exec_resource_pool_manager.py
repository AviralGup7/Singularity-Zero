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
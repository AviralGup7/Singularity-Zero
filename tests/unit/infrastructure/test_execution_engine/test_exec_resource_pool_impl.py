import asyncio
import unittest

import pytest

from src.infrastructure.execution_engine.resource_pool import (
    ResourcePool as ResourcePoolImpl,
)


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

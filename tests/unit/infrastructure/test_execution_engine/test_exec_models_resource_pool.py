import unittest

from src.infrastructure.execution_engine.models import (
    ResourcePool,
)


class TestResourcePoolModel(unittest.TestCase):
    def test_pool_defaults(self) -> None:
        pool = ResourcePool(name="test")
        assert pool.max_concurrent == 10
        assert pool.current_usage == 0
        assert pool.min_size == 1
        assert pool.max_size == 50
        assert pool.acquire_timeout_seconds == 30.0
        assert pool.health_check_interval_seconds == 60.0

import unittest

from src.infrastructure.execution_engine.models import (
    ExecutionConfig,
)


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

import unittest

import pytest

from src.infrastructure.execution_engine.config import (
    DEFAULT_EXECUTION_CONFIG,
    config_from_env,
    load_execution_config,
)
from src.infrastructure.execution_engine.models import (
    ExecutionConfig,
)


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

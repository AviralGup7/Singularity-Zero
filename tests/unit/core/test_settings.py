"""Unit tests for core.config.settings module."""

import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from src.core.config.settings import (
    AppSettings,
    CacheSettings,
    DashboardSettings,
    PipelineSettings,
    get_settings,
    load_settings,
)


@pytest.mark.unit
class TestSettings(unittest.TestCase):
    def setUp(self) -> None:
        # Reset cache before each test
        import src.core.config.settings as settings_mod
        settings_mod._settings_cache = None

    def test_default_settings(self) -> None:
        settings = get_settings(force_reload=True)
        self.assertEqual(settings.environment, "development")
        self.assertIsInstance(settings.pipeline, PipelineSettings)
        self.assertIsInstance(settings.dashboard, DashboardSettings)
        self.assertIsInstance(settings.cache, CacheSettings)

    def test_load_settings_from_json(self) -> None:
        test_json = {
            "defaults": {
                "pipeline": {"max_workers": 10},
            },
            "production": {
                "pipeline": {"max_workers": 20},
                "dashboard": {"port": 8080}
            }
        }

        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.read_text", return_value=json.dumps(test_json)):
                # Test defaults (assuming PIPELINE_ENV is development)
                with patch.dict(os.environ, {"PIPELINE_ENV": "development"}):
                    settings = load_settings(Path("dummy.json"))
                    self.assertEqual(settings.pipeline.max_workers, 10)

                # Test production overrides
                with patch.dict(os.environ, {"PIPELINE_ENV": "production"}):
                    settings = load_settings(Path("dummy.json"))
                    self.assertEqual(settings.pipeline.max_workers, 20)
                    self.assertEqual(settings.dashboard.port, 8080)

    def test_env_variable_overrides(self) -> None:
        env_vars = {
            "CYBER_PIPELINE__HTTPX_THREADS": "100",
            "CYBER_DASHBOARD__PORT": "9090",
            "CYBER_CACHE__PROBE_CACHE_ENABLED": "false"
        }
        with patch.dict(os.environ, env_vars, clear=True):
            settings = AppSettings()
            self.assertEqual(settings.pipeline.httpx_threads, 100)
            self.assertEqual(settings.dashboard.port, 9090)
            self.assertFalse(settings.cache.probe_cache_enabled)

    def test_invalid_type_coercion_fails(self) -> None:
        with patch.dict(os.environ, {"CYBER_PIPELINE__HTTPX_THREADS": "not_an_int"}, clear=True):
            with self.assertRaises(ValidationError):
                AppSettings()

if __name__ == "__main__":
    unittest.main()

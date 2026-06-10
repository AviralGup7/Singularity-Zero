import os
import unittest
from unittest.mock import MagicMock, patch

import pytest

from src.core.capabilities import CapabilityManifest
from src.pipeline.services.pipeline_orchestrator._orchestrator.bootstrap import bootstrap_pipeline
from src.pipeline.tools_capabilities import (
    CAPABILITY_PROVIDERS,
    CapabilityRegistry,
    resolve_capability,
)


@pytest.mark.unit
class TestCapabilityRegistry(unittest.TestCase):
    def test_registry_registration_and_lookup(self) -> None:
        registry = CapabilityRegistry()
        mock_provider = MagicMock()
        manifest = CapabilityManifest(
            estimated_duration_seconds=10.0,
            memory_mb=100.0,
            network_calls_per_target=5,
            supports_checkpoint_resume=True,
        )
        registry.register("test_capability", mock_provider, manifest)

        self.assertEqual(registry.get_provider("test_capability"), mock_provider)
        self.assertEqual(registry.get_manifest("test_capability"), manifest)
        self.assertIn("test_capability", registry.list_capabilities())

    def test_registry_raises_key_error_on_missing(self) -> None:
        registry = CapabilityRegistry()
        with self.assertRaises(KeyError):
            registry.get_provider("non_existent")
        with self.assertRaises(KeyError):
            registry.get_manifest("non_existent")

    def test_resolve_capability_helper(self) -> None:
        provider = resolve_capability("recon_provider")
        self.assertIsNotNone(provider)

    def test_default_providers_present_in_providers_dict(self) -> None:
        self.assertIn("recon_provider", CAPABILITY_PROVIDERS)
        self.assertIn("http_probe_provider", CAPABILITY_PROVIDERS)
        self.assertIn("crawler_provider", CAPABILITY_PROVIDERS)
        self.assertIn("template_scanner", CAPABILITY_PROVIDERS)


@pytest.mark.unit
class TestBootstrapResourceValidation(unittest.TestCase):
    @patch("psutil.virtual_memory")
    def test_bootstrap_memory_budget_exceeded(self, mock_virtual_memory) -> None:
        # Mock available memory to be very low (e.g., 50MB)
        mock_mem = MagicMock()
        mock_mem.available = 50 * 1024 * 1024  # 50MB
        mock_virtual_memory.return_value = mock_mem

        # Set up arguments and config
        args = MagicMock()
        args.config = "dummy_config.json"
        args.scope = "dummy_scope.txt"

        config = MagicMock()
        config.target_name = "test_target"
        config.tools = {
            "subfinder": True,  # triggers recon_provider (256MB required)
        }
        setattr(args, "_loaded_config", config)
        setattr(args, "_loaded_scope_entries", ["example.com"])

        # Run bootstrap, expecting ValueError due to insufficient memory
        # We temporarily clear the IGNORE env var if it's set in this test run environment
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError) as context:
                with patch(
                    "src.pipeline.services.pipeline_orchestrator._orchestrator.bootstrap.pipeline_flow_manifest"
                ):
                    with patch(
                        "src.pipeline.services.pipeline_orchestrator._orchestrator.bootstrap.build_tool_status"
                    ):
                        bootstrap_pipeline(args)

            self.assertIn("Insufficient host memory", str(context.exception))

    @patch("psutil.virtual_memory")
    def test_bootstrap_memory_budget_ignored_with_env(self, mock_virtual_memory) -> None:
        mock_mem = MagicMock()
        mock_mem.available = 50 * 1024 * 1024  # 50MB
        mock_virtual_memory.return_value = mock_mem

        args = MagicMock()
        args.config = "dummy_config.json"
        args.scope = "dummy_scope.txt"

        config = MagicMock()
        config.target_name = "test_target"
        config.tools = {
            "subfinder": True,
        }
        setattr(args, "_loaded_config", config)
        setattr(args, "_loaded_scope_entries", ["example.com"])

        # Run with IGNORE_CAPABILITY_RESOURCE_BUDGET=1, should succeed without raising ValueError
        with patch.dict(os.environ, {"IGNORE_CAPABILITY_RESOURCE_BUDGET": "1"}):
            with patch(
                "src.pipeline.services.pipeline_orchestrator._orchestrator.bootstrap.pipeline_flow_manifest"
            ):
                with patch(
                    "src.pipeline.services.pipeline_orchestrator._orchestrator.bootstrap.build_tool_status"
                ):
                    res_config, _, _, _ = bootstrap_pipeline(args)
                    self.assertEqual(res_config, config)

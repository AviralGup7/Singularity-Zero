"""Unit tests for src.core.capabilities."""

import unittest

import pytest

from src.core.capabilities import (
    SystemPluginManifest as CapabilityManifest,
)
from src.core.capabilities import (
    generate_capability_manifest,
)


@pytest.mark.unit
class TestCapabilityManifest(unittest.TestCase):
    def test_basic_construction(self) -> None:
        manifest = CapabilityManifest()
        self.assertIsNotNone(manifest)

    def test_default_generated_by(self) -> None:
        manifest = CapabilityManifest()
        self.assertIn("generate_capability_manifest", manifest.generated_by)

    def test_default_schema_version(self) -> None:
        manifest = CapabilityManifest()
        self.assertEqual(manifest.plugin_schema_version, "1.0")

    def test_default_providers_empty(self) -> None:
        manifest = CapabilityManifest()
        self.assertEqual(manifest.providers, {})

    def test_default_dynamic_plugins_empty(self) -> None:
        manifest = CapabilityManifest()
        self.assertEqual(manifest.dynamic_plugins, [])

    def test_default_invalid_dynamic_plugins_empty(self) -> None:
        manifest = CapabilityManifest()
        self.assertEqual(manifest.invalid_dynamic_plugins, [])

    def test_default_watched_dirs_empty(self) -> None:
        manifest = CapabilityManifest()
        self.assertEqual(manifest.watched_dirs, [])


@pytest.mark.unit
class TestGenerateCapabilityManifest(unittest.TestCase):
    def test_returns_capability_manifest(self) -> None:
        result = generate_capability_manifest()
        self.assertIsInstance(result, CapabilityManifest)

    def test_generated_by_field_populated(self) -> None:
        result = generate_capability_manifest()
        self.assertIn("generate_capability_manifest", result.generated_by)

    def test_schema_version_field_populated(self) -> None:
        result = generate_capability_manifest()
        self.assertEqual(result.plugin_schema_version, "1.0")

    def test_providers_is_dict(self) -> None:
        result = generate_capability_manifest()
        self.assertIsInstance(result.providers, dict)

    def test_dynamic_plugins_is_list(self) -> None:
        result = generate_capability_manifest()
        self.assertIsInstance(result.dynamic_plugins, list)

    def test_watched_dirs_is_list(self) -> None:
        result = generate_capability_manifest()
        self.assertIsInstance(result.watched_dirs, list)

    def test_returns_manifest_object_not_none(self) -> None:
        result = generate_capability_manifest()
        self.assertIsNotNone(result)

    def test_default_values_consistent(self) -> None:
        m1 = generate_capability_manifest()
        m2 = generate_capability_manifest()
        self.assertEqual(m1.plugin_schema_version, m2.plugin_schema_version)


@pytest.mark.unit
class TestCapabilityManifestDataclass(unittest.TestCase):
    def test_construction_with_fields(self) -> None:
        from src.core.capabilities import CapabilityManifest

        manifest = CapabilityManifest(
            estimated_duration_seconds=120.0,
            memory_mb=512.0,
            network_calls_per_target=100,
            supports_checkpoint_resume=True,
            version_requirements={"test": ">=1.0"},
        )
        self.assertEqual(manifest.estimated_duration_seconds, 120.0)
        self.assertEqual(manifest.memory_mb, 512.0)
        self.assertEqual(manifest.network_calls_per_target, 100)
        self.assertTrue(manifest.supports_checkpoint_resume)
        self.assertEqual(manifest.version_requirements["test"], ">=1.0")


@pytest.mark.unit
class TestToolExecutionContext(unittest.TestCase):
    def test_construction_with_fields(self) -> None:
        from src.core.capabilities import ToolExecutionContext

        context = ToolExecutionContext(
            resolved_paths={"tool": "/path/to/tool"},
            env={"VAR": "val"},
            sandbox_constraints={"limit": 10},
            config="test_config",
        )
        self.assertEqual(context.resolved_paths["tool"], "/path/to/tool")
        self.assertEqual(context.env["VAR"], "val")
        self.assertEqual(context.sandbox_constraints["limit"], 10)
        self.assertEqual(context.config, "test_config")


if __name__ == "__main__":
    unittest.main()

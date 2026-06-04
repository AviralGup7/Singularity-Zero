"""Unit tests for src.core.capabilities."""

import unittest

import pytest

from src.core.capabilities import (
    CapabilityManifest,
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


if __name__ == "__main__":
    unittest.main()

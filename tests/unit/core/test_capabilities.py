"""Unit tests for src.core.capabilities."""

import unittest

import pytest

from src.core.capabilities import CapabilityManifest, generate_capability_manifest


@pytest.mark.unit
class TestCapabilityManifest(unittest.TestCase):
    def test_defaults_have_correct_schema_version(self) -> None:
        m = CapabilityManifest()
        self.assertEqual(m.plugin_schema_version, "1.0")

    def test_default_generated_by_value(self) -> None:
        m = CapabilityManifest()
        self.assertEqual(m.generated_by, "src.core.capabilities.generate_capability_manifest")

    def test_default_providers_is_empty_dict(self) -> None:
        m = CapabilityManifest()
        self.assertEqual(m.providers, {})

    def test_default_dynamic_plugins_is_empty_list(self) -> None:
        m = CapabilityManifest()
        self.assertEqual(m.dynamic_plugins, [])

    def test_default_invalid_plugins_is_empty_list(self) -> None:
        m = CapabilityManifest()
        self.assertEqual(m.invalid_dynamic_plugins, [])

    def test_default_watched_dirs_is_empty_list(self) -> None:
        m = CapabilityManifest()
        self.assertEqual(m.watched_dirs, [])

    def test_to_dict_returns_dict_with_expected_keys(self) -> None:
        m = CapabilityManifest()
        data = m.to_dict()
        for key in (
            "generated_by",
            "plugin_schema_version",
            "providers",
            "dynamic_plugins",
            "invalid_dynamic_plugins",
            "watched_dirs",
        ):
            self.assertIn(key, data)

    def test_to_dict_preserves_values(self) -> None:
        m = CapabilityManifest(
            providers={"recon_provider": [{"key": "foo"}]},
            dynamic_plugins=[{"name": "x"}],
            invalid_dynamic_plugins=[{"name": "bad"}],
            watched_dirs=["/etc/plugins"],
        )
        data = m.to_dict()
        self.assertEqual(data["providers"], {"recon_provider": [{"key": "foo"}]})
        self.assertEqual(data["dynamic_plugins"], [{"name": "x"}])
        self.assertEqual(data["invalid_dynamic_plugins"], [{"name": "bad"}])
        self.assertEqual(data["watched_dirs"], ["/etc/plugins"])

    def test_manifest_is_frozen(self) -> None:
        m = CapabilityManifest()
        with self.assertRaises(Exception):
            m.plugin_schema_version = "2.0"  # type: ignore[misc]


@pytest.mark.unit
class TestGenerateCapabilityManifest(unittest.TestCase):
    def test_returns_capability_manifest_instance(self) -> None:
        manifest = generate_capability_manifest()
        self.assertIsInstance(manifest, CapabilityManifest)

    def test_providers_contains_expected_kinds(self) -> None:
        manifest = generate_capability_manifest()
        for kind in (
            "recon_provider",
            "scanner",
            "validator",
            "exporter",
            "enrichment_provider",
            "detector_spec",
            "dynamic_plugin",
        ):
            self.assertIn(kind, manifest.providers)


if __name__ == "__main__":
    unittest.main()

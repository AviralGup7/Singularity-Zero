import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.pipeline.storage import load_config
from src.recon.subdomains import enumerate_subdomains, fetch_crtsh_subdomains


class ReconSubdomainTests(unittest.TestCase):
    def test_enumerate_subdomains_seeds_roots_from_wildcard_scope_entries(self) -> None:
        config = {
            "tools": {"subfinder": False, "assetfinder": False, "amass": False, "timeout_seconds": 1},
            "http_timeout_seconds": 1,
        }

        result = enumerate_subdomains(
            ["*.square.com", "*.squareup.com", "square.online"], config, True
        )

        self.assertIn("square.com", result)
        self.assertIn("squareup.com", result)
        self.assertIn("square.online", result)

    def test_enumerate_subdomains_keeps_seed_roots_when_crtsh_returns_empty(self) -> None:
        config = {
            "tools": {"subfinder": False, "assetfinder": False, "amass": False, "timeout_seconds": 1},
            "http_timeout_seconds": 1,
        }

        with patch("src.recon.subdomains.fetch_crtsh_subdomains", return_value=set()):
            result = enumerate_subdomains(["*.example.com"], config, False)

        self.assertEqual(result, {"example.com"})

    def test_fetch_crtsh_subdomains_handles_socket_timeout(self) -> None:
        with patch(
            "src.recon.subdomains.requests.get",
            side_effect=TimeoutError("The read operation timed out"),
        ):
            result = fetch_crtsh_subdomains("example.com", 3)

        self.assertEqual(result, set())

    def test_fetch_crtsh_subdomains_parses_wildcard_and_multiline_names(self) -> None:
        payload = '[{"name_value":"*.api.example.com\\nshop.example.com"}]'

        class FakeResponse:
            def read(self) -> str:
                return payload

            @property
            def text(self) -> str:
                return payload

        with patch("src.recon.subdomains.requests.get", return_value=FakeResponse()):
            result = fetch_crtsh_subdomains("example.com", 3)

        self.assertEqual(result, {"api.example.com", "shop.example.com"})

    def test_load_config_supports_new_analysis_flags_used_by_latest_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            config_path.write_text(
                (
                    "{"
                    '"target_name":"demo",'
                    '"output_dir":"output",'
                    '"analysis":{'
                    '"ai_endpoint_exposure_analyzer":true,'
                    '"cross_tenant_pii_risk_analyzer":true,'
                    '"server_side_injection_surface_analyzer":true'
                    "}"
                    "}"
                ),
                encoding="utf-8",
            )

            config = load_config(config_path)

        self.assertTrue(config.analysis["ai_endpoint_exposure_analyzer"])
        self.assertTrue(config.analysis["cross_tenant_pii_risk_analyzer"])
        self.assertTrue(config.analysis["server_side_injection_surface_analyzer"])


if __name__ == "__main__":
    unittest.main()

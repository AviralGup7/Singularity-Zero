"""Unit tests for the vulnerable component detector integration and functionality."""

import unittest
from typing import Any

from src.analysis.passive.detector_vulnerable_components import vulnerable_component_detector
from src.analysis.plugin_runtime import ANALYZER_BINDINGS


class VulnerableComponentDetectorRegistrationTests(unittest.TestCase):
    """Verify the detector is registered in the analysis catalog."""

    def test_detector_registered_in_analyzer_bindings(self) -> None:
        self.assertIn("vulnerable_component_detector", ANALYZER_BINDINGS)

    def test_binding_has_correct_input_kind(self) -> None:
        binding = ANALYZER_BINDINGS["vulnerable_component_detector"]
        self.assertEqual(binding.input_kind, "urls_and_responses")

    def test_binding_has_callable_runner(self) -> None:
        binding = ANALYZER_BINDINGS["vulnerable_component_detector"]
        self.assertTrue(callable(binding.runner))

    def test_binding_runner_is_correct_function(self) -> None:
        from src.analysis.passive.detectors.detector_vulnerable_components import (
            vulnerable_component_detector as runtime_detector,
        )

        binding = ANALYZER_BINDINGS["vulnerable_component_detector"]
        self.assertIs(binding.runner, runtime_detector)


class VulnerableComponentDetectorFunctionalityTests(unittest.TestCase):
    """Verify the detector processes sample responses correctly."""

    def _make_response(
        self,
        url: str = "https://example.com/api",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body_text: str = "",
    ) -> dict[str, Any]:
        return {
            "url": url,
            "status_code": status_code,
            "headers": headers or {},
            "body_text": body_text,
        }

    def test_no_findings_for_clean_response(self) -> None:
        responses = [self._make_response(headers={"Content-Type": "application/json"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 0)

    def test_no_findings_for_empty_responses(self) -> None:
        findings = vulnerable_component_detector(set(), [])
        self.assertEqual(len(findings), 0)

    def test_finds_with_noise_url_are_skipped(self) -> None:
        responses = [
            self._make_response(
                url="https://example.com/favicon.ico",
                headers={"Server": "Apache/2.4.49"},
            )
        ]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 0)


class VulnerableComponentDetectorServerVersionTests(unittest.TestCase):
    """Test detection of server version disclosure."""

    def _make_response(
        self,
        url: str = "https://example.com/api",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body_text: str = "",
    ) -> dict[str, Any]:
        return {
            "url": url,
            "status_code": status_code,
            "headers": headers or {},
            "body_text": body_text,
        }

    def test_detects_apache_version(self) -> None:
        responses = [self._make_response(headers={"Server": "Apache/2.4.49"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("server_version_disclosure", findings[0]["signals"])
        evidence = findings[0]["evidence"]["server_issues"]
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["technology"], "Apache")

    def test_detects_nginx_version(self) -> None:
        responses = [self._make_response(headers={"Server": "nginx/1.18.0"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("server_version_disclosure", findings[0]["signals"])

    def test_detects_iis_version(self) -> None:
        responses = [self._make_response(headers={"Server": "Microsoft-IIS/10.0"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("server_version_disclosure", findings[0]["signals"])

    def test_detects_known_vulnerable_apache(self) -> None:
        responses = [self._make_response(headers={"Server": "Apache/2.2.15"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("vulnerable_version", findings[0]["signals"])
        vuln_versions = findings[0]["evidence"]["vulnerable_versions"]
        self.assertTrue(any(v["component"] == "Apache 2.2.x" for v in vuln_versions))

    def test_detects_known_vulnerable_nginx(self) -> None:
        responses = [self._make_response(headers={"Server": "nginx/1.9.0"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("vulnerable_version", findings[0]["signals"])

    def test_detects_known_vulnerable_iis(self) -> None:
        responses = [self._make_response(headers={"Server": "Microsoft-IIS/6.0"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        vuln_versions = findings[0]["evidence"]["vulnerable_versions"]
        self.assertTrue(any(v["severity"] == "critical" for v in vuln_versions))


class VulnerableComponentDetectorPoweredByTests(unittest.TestCase):
    """Test detection of X-Powered-By headers."""

    def _make_response(
        self,
        url: str = "https://example.com/api",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body_text: str = "",
    ) -> dict[str, Any]:
        return {
            "url": url,
            "status_code": status_code,
            "headers": headers or {},
            "body_text": body_text,
        }

    def test_detects_php_version(self) -> None:
        responses = [self._make_response(headers={"X-Powered-By": "PHP/7.4.3"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("powered_by_disclosure", findings[0]["signals"])
        powered_by = findings[0]["evidence"]["powered_by_issues"]
        self.assertEqual(len(powered_by), 1)
        self.assertEqual(powered_by[0]["technology"], "PHP")

    def test_detects_express_framework(self) -> None:
        responses = [self._make_response(headers={"X-Powered-By": "Express"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("powered_by_disclosure", findings[0]["signals"])

    def test_detects_asp_net(self) -> None:
        responses = [self._make_response(headers={"X-Powered-By": "ASP.NET"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("powered_by_disclosure", findings[0]["signals"])

    def test_detects_django(self) -> None:
        responses = [self._make_response(headers={"X-Powered-By": "Django/3.1.0"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("powered_by_disclosure", findings[0]["signals"])
        self.assertIn("vulnerable_version", findings[0]["signals"])

    def test_detects_vulnerable_php_version(self) -> None:
        responses = [self._make_response(headers={"X-Powered-By": "PHP/5.3.0"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        vuln_versions = findings[0]["evidence"]["vulnerable_versions"]
        self.assertTrue(any(v["severity"] == "critical" for v in vuln_versions))


class VulnerableComponentDetectorFrameworkHeadersTests(unittest.TestCase):
    """Test detection of framework-specific headers."""

    def _make_response(
        self,
        url: str = "https://example.com/api",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body_text: str = "",
    ) -> dict[str, Any]:
        return {
            "url": url,
            "status_code": status_code,
            "headers": headers or {},
            "body_text": body_text,
        }

    def test_detects_aspnet_version_header(self) -> None:
        responses = [self._make_response(headers={"X-AspNet-Version": "4.0.30319"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("framework_header", findings[0]["signals"])
        framework = findings[0]["evidence"]["framework_issues"]
        self.assertTrue(any(f["technology"] == "ASP.NET" for f in framework))

    def test_detects_x_runtime_header(self) -> None:
        responses = [self._make_response(headers={"X-Runtime": "0.045332"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("framework_header", findings[0]["signals"])

    def test_detects_x_generator_header(self) -> None:
        responses = [self._make_response(headers={"X-Generator": "WordPress 5.8"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("framework_header", findings[0]["signals"])

    def test_detects_envoy_header(self) -> None:
        responses = [self._make_response(headers={"X-Envoy-Upstream-Service-Time": "12"})]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("framework_header", findings[0]["signals"])


class VulnerableComponentDetectorDebugIndicatorsTests(unittest.TestCase):
    """Test detection of debug/development mode indicators."""

    def _make_response(
        self,
        url: str = "https://example.com/api",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body_text: str = "",
    ) -> dict[str, Any]:
        return {
            "url": url,
            "status_code": status_code,
            "headers": headers or {},
            "body_text": body_text,
        }

    def test_detects_debug_mode_in_body(self) -> None:
        responses = [self._make_response(body_text="debug: true")]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("debug_mode", findings[0]["signals"])

    def test_detects_stack_trace_exposure(self) -> None:
        responses = [
            self._make_response(body_text="Traceback (most recent call last):\n  File app.py")
        ]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("debug_mode", findings[0]["signals"])

    def test_detects_sql_error_exposure(self) -> None:
        responses = [self._make_response(body_text="SQL syntax error near 'SELECT * FROM users'")]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("debug_mode", findings[0]["signals"])

    def test_detects_flask_debugger(self) -> None:
        responses = [self._make_response(body_text="Flask Debugger enabled")]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        debug = findings[0]["evidence"]["debug_indicators"]
        self.assertTrue(any("Flask debugger" in d["indicator"] for d in debug))

    def test_detects_debug_header(self) -> None:
        responses = [
            self._make_response(
                headers={"X-Debug-Token": "abc123"},
                body_text="some content",
            )
        ]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("debug_mode", findings[0]["signals"])

    def test_detects_development_environment_header(self) -> None:
        responses = [
            self._make_response(
                headers={"X-Environment": "development"},
                body_text="some content",
            )
        ]
        findings = vulnerable_component_detector(set(), responses)
        self.assertEqual(len(findings), 1)
        self.assertIn("debug_mode", findings[0]["signals"])


if __name__ == "__main__":
    unittest.main()

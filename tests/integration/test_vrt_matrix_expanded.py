import unittest
from pathlib import Path
from typing import Any

from src.pipeline.storage import load_config
from src.reporting.vrt_coverage import build_p1_vrt_coverage


def _coverage_by_key(coverage: dict[str, Any]) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {
        (item["vrt_category"], item["vulnerability_name"], item["variant"]): item
        for item in coverage["entries"]
    }


class VrtCoverageMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load_config(Path("configs/config.example.json"))

    def test_summary_counts_match_expected_catalog_breakdown(self) -> None:
        summary = build_p1_vrt_coverage(self.config)["summary"]

        self.assertEqual(summary["requested_total"], 30)
        self.assertEqual(summary["direct"], 10)
        self.assertEqual(summary["signal_only"], 11)
        self.assertEqual(summary["disabled"], 0)
        self.assertEqual(summary["unsupported"], 9)

    def test_direct_coverage_includes_expected_high_risk_web_categories(self) -> None:
        coverage = _coverage_by_key(build_p1_vrt_coverage(self.config))

        direct_cases = [
            (
                "Broken Access Control (BAC)",
                "Insecure Direct Object References (IDOR)",
                "Modify/View Sensitive Information(Iterable Object Identifiers)",
            ),
            ("Broken Authentication and Session Management", "Authentication Bypass", ""),
            (
                "AI Application Security",
                "Sensitive Information Disclosure",
                "Cross-Tenant PII Leakage/Exposure",
            ),
            ("AI Application Security", "Sensitive Information Disclosure", "Key Leak"),
            (
                "Cloud Security",
                "Identity and Access Management (IAM) Misconfigurations",
                "Publicly Accessible IAM Credentials",
            ),
            (
                "Decentralized Application Misconfiguration",
                "Insecure Data Storage",
                "Plaintext Private Key",
            ),
            ("Sensitive Data Exposure", "Disclosure of Secrets", "For Publicly Accessible Asset"),
            ("Server Security Misconfiguration", "Exposed Portal", "Admin Portal"),
            ("Server Security Misconfiguration", "Using Default Credentials", ""),
        ]

        for key in direct_cases:
            with self.subTest(key=key):
                self.assertEqual(coverage[key]["status"], "direct")
                self.assertTrue(coverage[key]["active_checks"])

    def test_signal_only_coverage_includes_surface_only_categories(self) -> None:
        coverage = _coverage_by_key(build_p1_vrt_coverage(self.config))

        signal_only_cases = [
            ("AI Application Security", "Model Extraction", "API Query-Based Model Reconstruction"),
            ("AI Application Security", "Remote Code Execution", "Full System Compromise"),
            ("Insecure OS/Firmware", "Command Injection", ""),
            ("Server-Side Injection", "File Inclusion", "Local"),
            ("Server-Side Injection", "Remote Code Execution (RCE)", ""),
            ("Server-Side Injection", "SQL Injection", ""),
            ("Server-Side Injection", "XML External Entity Injection (XXE)", ""),
            (
                "Decentralized Application Misconfiguration",
                "Protocol Security Misconfiguration",
                "Node-level Denial of Service",
            ),
        ]

        for key in signal_only_cases:
            with self.subTest(key=key):
                self.assertEqual(coverage[key]["status"], "signal_only")
                self.assertTrue(coverage[key]["active_checks"])

    def test_unsupported_entries_remain_out_of_scope_families(self) -> None:
        coverage = _coverage_by_key(build_p1_vrt_coverage(self.config))

        unsupported_cases = [
            (
                "AI Application Security",
                "Training Data Poisoning",
                "Backdoor Injection / Bias Manipulation",
            ),
            (
                "Automotive Security Misconfiguration",
                "Infotainment, Radio Head Unit",
                "Sensitive data Leakage/Exposure",
            ),
            ("Automotive Security Misconfiguration", "RF Hub", "Key Fob Cloning"),
            ("Smart Contract Misconfiguration", "Reentrancy Attack", ""),
            ("Smart Contract Misconfiguration", "Smart Contract Owner Takeover", ""),
            ("Smart Contract Misconfiguration", "Unauthorized Transfer of Funds", ""),
            ("Smart Contract Misconfiguration", "Uninitialized Variables", ""),
            ("Zero Knowledge Security Misconfiguration", "Deanonymization of Data", ""),
            (
                "Zero Knowledge Security Misconfiguration",
                "Improper Proof Validation and Finalization Logic",
                "",
            ),
        ]

        for key in unsupported_cases:
            with self.subTest(key=key):
                self.assertEqual(coverage[key]["status"], "unsupported")
                self.assertEqual(coverage[key]["active_checks"], [])

    def test_disabling_plaintext_private_key_check_marks_entry_disabled(self) -> None:
        self.config.analysis["sensitive_data_scanner"] = False

        coverage = _coverage_by_key(build_p1_vrt_coverage(self.config))
        entry = coverage[
            (
                "Decentralized Application Misconfiguration",
                "Insecure Data Storage",
                "Plaintext Private Key",
            )
        ]

        self.assertEqual(entry["status"], "disabled")
        self.assertEqual(entry["active_checks"], [])

    def test_disabling_all_auth_bypass_checks_marks_entry_disabled(self) -> None:
        for check_name in (
            "unauth_access_check",
            "multi_endpoint_auth_consistency_check",
            "access_boundary_tracker",
            "auth_boundary_redirect_detection",
        ):
            self.config.analysis[check_name] = False

        coverage = _coverage_by_key(build_p1_vrt_coverage(self.config))
        entry = coverage[
            ("Broken Authentication and Session Management", "Authentication Bypass", "")
        ]

        self.assertEqual(entry["status"], "disabled")
        self.assertEqual(entry["active_checks"], [])

    def test_disabling_server_side_injection_surface_marks_sqli_disabled(self) -> None:
        self.config.analysis["server_side_injection_surface_analyzer"] = False
        self.config.analysis["error_based_inference"] = False

        coverage = _coverage_by_key(build_p1_vrt_coverage(self.config))
        entry = coverage[("Server-Side Injection", "SQL Injection", "")]

        self.assertEqual(entry["status"], "disabled")
        self.assertEqual(entry["active_checks"], [])

    def test_every_catalog_entry_has_notes_and_declared_checks(self) -> None:
        coverage = build_p1_vrt_coverage(self.config)

        for item in coverage["entries"]:
            with self.subTest(item=item["vulnerability_name"], variant=item["variant"]):
                self.assertTrue(item["notes"].strip())
                self.assertIsInstance(item["direct_checks"], list)
                self.assertIsInstance(item["signal_checks"], list)
                self.assertTrue(
                    set(item["active_checks"]).issubset(
                        set(item["direct_checks"]) | set(item["signal_checks"])
                    )
                )


if __name__ == "__main__":
    unittest.main()

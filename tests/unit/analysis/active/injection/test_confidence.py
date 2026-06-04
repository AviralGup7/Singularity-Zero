"""Unit tests for src.analysis.active.injection._confidence."""

import unittest

import pytest

from src.analysis.active.injection._confidence import (
    PROBE_CONFIDENCE_MAP,
    PROBE_SEVERITY_MAP,
    probe_confidence,
    probe_confidence_from_map,
    probe_severity,
    probe_severity_from_map,
)


@pytest.mark.unit
class TestProbeConfidenceMap(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(PROBE_CONFIDENCE_MAP, dict)

    def test_values_in_unit_range(self) -> None:
        for conf in PROBE_CONFIDENCE_MAP.values():
            self.assertGreaterEqual(conf, 0.0)
            self.assertLessEqual(conf, 1.0)

    def test_contains_path_traversal_keys(self) -> None:
        for key in (
            "path_traversal_file_read",
            "path_traversal_etc_passwd_reflection",
        ):
            self.assertIn(key, PROBE_CONFIDENCE_MAP)

    def test_contains_ssrf_keys(self) -> None:
        for key in ("ssrf_internal_ip_response", "ssrf_cloud_metadata"):
            self.assertIn(key, PROBE_CONFIDENCE_MAP)

    def test_contains_crlf_keys(self) -> None:
        for key in ("crlf_header_injection", "crlf_response_split"):
            self.assertIn(key, PROBE_CONFIDENCE_MAP)

    def test_contains_ssti_keys(self) -> None:
        for key in ("ssti_arithmetic_reflection", "ssti_error_pattern"):
            self.assertIn(key, PROBE_CONFIDENCE_MAP)

    def test_contains_ldap_keys(self) -> None:
        for key in ("ldap_auth_bypass", "ldap_error_pattern"):
            self.assertIn(key, PROBE_CONFIDENCE_MAP)

    def test_minimum_entries(self) -> None:
        self.assertGreaterEqual(len(PROBE_CONFIDENCE_MAP), 30)


@pytest.mark.unit
class TestProbeSeverityMap(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(PROBE_SEVERITY_MAP, dict)

    def test_values_are_valid_severity(self) -> None:
        for sev in PROBE_SEVERITY_MAP.values():
            self.assertIn(sev, {"critical", "high", "medium", "low"})

    def test_keys_match_confidence_map(self) -> None:
        self.assertEqual(
            set(PROBE_CONFIDENCE_MAP.keys()),
            set(PROBE_SEVERITY_MAP.keys()),
        )

    def test_file_read_is_critical(self) -> None:
        self.assertEqual(PROBE_SEVERITY_MAP["path_traversal_file_read"], "critical")

    def test_open_redirect_is_medium_or_lower(self) -> None:
        for key in (
            "open_redirect_location_header",
            "open_redirect_status_3xx",
        ):
            self.assertIn(PROBE_SEVERITY_MAP[key], {"medium", "low"})


@pytest.mark.unit
class TestProbeConfidenceFn(unittest.TestCase):
    def test_returns_default_when_no_map(self) -> None:
        self.assertEqual(probe_confidence(["a", "b"]), 0.5)

    def test_uses_map_when_provided(self) -> None:
        m = {"a": 0.9, "b": 0.7}
        # max is 0.9 + bonus 0.04 capped at 0.98
        result = probe_confidence(["a", "b"], confidence_map=m)
        self.assertAlmostEqual(result, 0.94, places=2)

    def test_cap_applies(self) -> None:
        m = {"a": 0.99}
        result = probe_confidence(["a"] * 5, confidence_map=m)
        self.assertLessEqual(result, 0.98)

    def test_unknown_issues_use_default(self) -> None:
        # default (0.5) + bonus for 1 issue (min(0.06, 0.02) = 0.02) = 0.52
        result = probe_confidence(["unknown_issue"], confidence_map={"a": 0.9})
        self.assertAlmostEqual(result, 0.52, places=2)

    def test_empty_issues_returns_default(self) -> None:
        m = {"a": 0.9}
        self.assertEqual(probe_confidence([], confidence_map=m), 0.5)


@pytest.mark.unit
class TestProbeSeverityFn(unittest.TestCase):
    def test_returns_default_when_no_map(self) -> None:
        self.assertEqual(probe_severity(["a"]), "low")

    def test_returns_highest_severity(self) -> None:
        m = {"a": "low", "b": "critical", "c": "medium"}
        self.assertEqual(probe_severity(["a", "b", "c"], severity_map=m), "critical")

    def test_empty_issues_returns_default(self) -> None:
        m = {"a": "high"}
        self.assertEqual(probe_severity([], severity_map=m), "low")

    def test_unknown_issues_returns_default(self) -> None:
        m = {"a": "high"}
        self.assertEqual(probe_severity(["unknown"], severity_map=m), "low")


@pytest.mark.unit
class TestProbeConfidenceFromMap(unittest.TestCase):
    def test_max_confidence_picked(self) -> None:
        m = {"a": 0.5, "b": 0.9}
        result = probe_confidence_from_map(["a", "b"], m)
        # 0.9 + 0.04 bonus = 0.94
        self.assertAlmostEqual(result, 0.94, places=2)

    def test_bonus_caps_at_six_percent(self) -> None:
        m = {"a": 0.5}
        result = probe_confidence_from_map(["a"] * 10, m)
        # 0.5 + min(0.06, 0.2) capped at 0.98 -> 0.56
        self.assertAlmostEqual(result, 0.56, places=2)


@pytest.mark.unit
class TestProbeSeverityFromMap(unittest.TestCase):
    def test_returns_highest(self) -> None:
        m = {"a": "low", "b": "high"}
        self.assertEqual(probe_severity_from_map(["a", "b"], m), "high")

    def test_no_matches_returns_default(self) -> None:
        self.assertEqual(probe_severity_from_map(["x"], {"a": "high"}), "low")


if __name__ == "__main__":
    unittest.main()

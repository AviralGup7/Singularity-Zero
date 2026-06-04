"""Unit tests for src.analysis.active.auth_bypass.auth_bypass_utils."""

import unittest

import pytest

from src.analysis.active.auth_bypass.auth_bypass_utils import (
    AUTH_BYPASS_CONFIDENCE,
    AUTH_BYPASS_PARAMS,
    AUTH_BYPASS_SEVERITY,
    AUTH_HEADERS,
    JWT_RE,
    _extract_jwt_from_headers,
    _has_auth_indicator,
)


@pytest.mark.unit
class TestJwtRegex(unittest.TestCase):
    def test_matches_standard_jwt(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturepart"
        self.assertIsNotNone(JWT_RE.search(token))

    def test_matches_jwt_with_underscores(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc_def-ghi"
        self.assertIsNotNone(JWT_RE.search(token))

    def test_does_not_match_non_jwt(self) -> None:
        self.assertIsNone(JWT_RE.search("not.a.jwt"))


@pytest.mark.unit
class TestAuthHeaders(unittest.TestCase):
    def test_contains_authorization(self) -> None:
        self.assertIn("Authorization", AUTH_HEADERS)

    def test_contains_x_api_key(self) -> None:
        self.assertIn("X-Api-Key", AUTH_HEADERS)

    def test_is_list(self) -> None:
        self.assertIsInstance(AUTH_HEADERS, list)

    def test_all_strings(self) -> None:
        for h in AUTH_HEADERS:
            self.assertIsInstance(h, str)


@pytest.mark.unit
class TestAuthBypassParams(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(AUTH_BYPASS_PARAMS, dict)

    def test_admin_param_has_truthy_values(self) -> None:
        self.assertIn("true", AUTH_BYPASS_PARAMS["admin"])

    def test_role_param_has_admin(self) -> None:
        self.assertIn("admin", AUTH_BYPASS_PARAMS["role"])

    def test_token_param_has_null(self) -> None:
        self.assertIn("null", AUTH_BYPASS_PARAMS["token"])

    def test_debug_param(self) -> None:
        self.assertEqual(AUTH_BYPASS_PARAMS["debug"], ["true", "1"])

    def test_values_are_lists(self) -> None:
        for v in AUTH_BYPASS_PARAMS.values():
            self.assertIsInstance(v, list)


@pytest.mark.unit
class TestAuthBypassConfidence(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(AUTH_BYPASS_CONFIDENCE, dict)

    def test_values_in_unit_range(self) -> None:
        for conf in AUTH_BYPASS_CONFIDENCE.values():
            self.assertGreaterEqual(conf, 0.0)
            self.assertLessEqual(conf, 1.0)

    def test_critical_bypass_high_confidence(self) -> None:
        self.assertGreaterEqual(AUTH_BYPASS_CONFIDENCE["jwt_stripping_bypass"], 0.85)

    def test_keys_match_severity_keys(self) -> None:
        self.assertEqual(
            set(AUTH_BYPASS_CONFIDENCE.keys()),
            set(AUTH_BYPASS_SEVERITY.keys()),
        )


@pytest.mark.unit
class TestAuthBypassSeverity(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(AUTH_BYPASS_SEVERITY, dict)

    def test_valid_severity_values(self) -> None:
        for sev in AUTH_BYPASS_SEVERITY.values():
            self.assertIn(sev, {"critical", "high", "medium", "low"})

    def test_jwt_stripping_is_critical(self) -> None:
        self.assertEqual(AUTH_BYPASS_SEVERITY["jwt_stripping_bypass"], "critical")

    def test_param_bypass_role_admin_critical(self) -> None:
        self.assertEqual(AUTH_BYPASS_SEVERITY["param_bypass_role_admin"], "critical")


@pytest.mark.unit
class TestHasAuthIndicator(unittest.TestCase):
    def test_detects_authorization_header(self) -> None:
        self.assertTrue(_has_auth_indicator({"Authorization": "Bearer xyz"}, ""))

    def test_detects_x_api_key(self) -> None:
        self.assertTrue(_has_auth_indicator({"X-Api-Key": "abc"}, ""))

    def test_case_insensitive_header(self) -> None:
        self.assertTrue(_has_auth_indicator({"authorization": "Bearer x"}, ""))

    def test_no_indicator(self) -> None:
        self.assertFalse(_has_auth_indicator({}, ""))

    def test_detects_authenticated_in_body(self) -> None:
        self.assertTrue(_has_auth_indicator({}, "user is authenticated"))

    def test_detects_token_valid_in_body(self) -> None:
        self.assertTrue(_has_auth_indicator({}, "token_valid: true"))


@pytest.mark.unit
class TestExtractJwtFromHeaders(unittest.TestCase):
    def test_extracts_bare_jwt(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = _extract_jwt_from_headers({"Authorization": token})
        self.assertEqual(result, token)

    def test_extracts_bearer_jwt(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = _extract_jwt_from_headers({"Authorization": f"Bearer {token}"})
        self.assertEqual(result, token)

    def test_no_jwt_returns_none(self) -> None:
        self.assertIsNone(_extract_jwt_from_headers({"Authorization": "Basic abc"}))

    def test_no_auth_header_returns_none(self) -> None:
        self.assertIsNone(_extract_jwt_from_headers({}))

    def test_x_api_key_with_jwt(self) -> None:
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        result = _extract_jwt_from_headers({"X-Api-Key": token})
        self.assertEqual(result, token)


if __name__ == "__main__":
    unittest.main()

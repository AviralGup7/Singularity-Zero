"""Tests for OAuth, SAML, and OAuth+SAML validators."""

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import MagicMock

from src.execution.validators.config.scoring_config import ScoringConfig
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.oauth import evaluate_oauth
from src.execution.validators.validators.oauth_saml import (
    evaluate_oauth_saml,
    summarize_findings,
    validate,
)
from src.execution.validators.validators.saml import evaluate_saml
from src.execution.validators.validators.shared import to_validation_result


class _StubScoring(ScoringConfig):
    def __init__(self, **overrides: object) -> None:
        super().__init__(**overrides)


class TestSamlValidator(unittest.TestCase):
    def test_no_endpoint_returns_inconclusive(self) -> None:
        result = evaluate_saml(
            acs_endpoint=None,
            scorings=_StubScoring(),
            http_request=None,
            in_scope=True,
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)
        self.assertEqual(result["confidence"], 0.0)

    def test_empty_response_accepted(self) -> None:
        mock_http = MagicMock(
            return_value={"status_code": 200, "body": "authenticated", "headers": {}}
        )
        result = evaluate_saml(
            acs_endpoint="https://target.com/saml/acs",
            scorings=_StubScoring(base=0.45, cap=0.93),
            http_request=mock_http,
            in_scope=True,
        )
        self.assertIn("saml_empty_response_accepted", result["signals"])
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)

    def test_signature_wrapping_detected(self) -> None:
        call_count = [0]

        def mock_http(method: str, url: str, data: Any = None) -> dict[str, Any]:
            call_count[0] += 1
            if call_count[0] == 1:
                return {"status_code": 403, "body": "error", "headers": {}}
            return {"status_code": 200, "body": "authenticated", "headers": {}}

        result = evaluate_saml(
            acs_endpoint="https://target.com/saml/acs",
            scorings=_StubScoring(base=0.45, cap=0.93),
            http_request=mock_http,
            in_scope=True,
        )
        self.assertIn("saml_signature_wrapping", result["signals"])

    def test_out_of_scope_no_signals(self) -> None:
        mock_http = MagicMock(
            return_value={"status_code": 200, "body": "authenticated", "headers": {}}
        )
        result = evaluate_saml(
            acs_endpoint="https://target.com/saml/acs",
            scorings=_StubScoring(base=0.45, cap=0.93),
            http_request=mock_http,
            in_scope=False,
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)
        self.assertEqual(result["signals"], [])


class TestOauthValidator(unittest.TestCase):
    def test_no_http_request_returns_inconclusive(self) -> None:
        result = evaluate_oauth(
            authorize_endpoint="https://target.com/oauth/authorize",
            scoring=_StubScoring(base=0.45, cap=0.93),
            http_request=None,
            in_scope=True,
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)
        self.assertEqual(result["confidence"], 0.0)

    def test_redirect_uri_bypass_detected(self) -> None:
        mock_http = MagicMock(
            return_value={
                "status_code": 302,
                "body": "",
                "headers": {"location": "https://evil.com/oauth_callback"},
            }
        )
        result = evaluate_oauth(
            authorize_endpoint="https://target.com/oauth/authorize",
            scoring=_StubScoring(base=0.45, cap=0.93),
            http_request=mock_http,
            in_scope=True,
        )
        signal_names = [s[0] if isinstance(s, tuple) else s for s in result["signals"]]
        self.assertIn("redirect_uri_bypass", signal_names)
        self.assertEqual(result["status"], ValidationStatus.CONFIRMED.value)

    def test_state_parameter_missing(self) -> None:
        mock_http = MagicMock(
            return_value={
                "status_code": 302,
                "body": "",
                "headers": {"location": "https://target.com/callback?code=abc123"},
            }
        )
        result = evaluate_oauth(
            authorize_endpoint="https://target.com/oauth/authorize",
            scoring=_StubScoring(base=0.45, cap=0.93),
            http_request=mock_http,
            in_scope=True,
        )
        signal_names = [s[0] if isinstance(s, tuple) else s for s in result["signals"]]
        self.assertIn("state_missing", signal_names)

    def test_out_of_scope_no_signals(self) -> None:
        mock_http = MagicMock(
            return_value={
                "status_code": 302,
                "body": "",
                "headers": {"location": "https://evil.com/callback"},
            }
        )
        result = evaluate_oauth(
            authorize_endpoint="https://target.com/oauth/authorize",
            scoring=_StubScoring(base=0.45, cap=0.93),
            http_request=mock_http,
            in_scope=False,
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)
        self.assertEqual(result["signals"], [])


class TestOauthSamlValidator(unittest.TestCase):
    def test_no_data_returns_inconclusive(self) -> None:
        result = validate(
            target={"url": "https://target.com"},
            context={},
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)
        self.assertEqual(result["confidence"], 0.0)

    def test_redirect_uri_reflected_in_response(self) -> None:
        result = validate(
            target={"url": "https://target.com"},
            context={
                "oauth_redirect_uri": "https://client.example.com/callback",
                "response_body": "redirect_uri=https://client.example.com/callback",
                "response_status": 302,
                "in_scope": True,
            },
        )
        self.assertIn("redirect_uri_reflected", result.get("evidence", {}).get("signals", []))

    def test_evaluate_oauth_saml_no_data(self) -> None:
        result = evaluate_oauth_saml(
            redirect_uri="",
            state_value=None,
            grant_type=None,
            saml_body=None,
            response_body="",
            response_headers={},
            response_status=0,
            scoring=_StubScoring(base=0.45, cap=0.93),
            in_scope=True,
        )
        self.assertEqual(result["status"], ValidationStatus.INCONCLUSIVE.value)

    def test_summarize_findings_empty(self) -> None:
        result = summarize_findings([])
        self.assertEqual(result["status"], "no_findings")
        self.assertEqual(result["count"], 0)

    def test_summarize_findings_with_signals(self) -> None:
        findings = [
            {
                "evidence": {
                    "signals": ["redirect_uri_bypass", "saml_signature_bypass"],
                }
            },
            {
                "evidence": {
                    "signals": ["oauth_state_empty_accepted"],
                }
            },
        ]
        result = summarize_findings(findings)
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["redirect_uri_bypass_count"], 1)
        self.assertEqual(result["saml_signature_bypass_count"], 1)
        self.assertEqual(result["state_empty_count"], 1)


class TestValidatorWrappers(unittest.TestCase):
    def test_saml_wrapper(self) -> None:
        from src.execution.validators.validators.registry_builder import _validate_saml

        result = _validate_saml(
            target={"url": "https://target.com/saml/acs"},
            context={"in_scope": True},
        )
        self.assertEqual(result["validator"], "saml")
        self.assertEqual(result["category"], "saml")
        self.assertIn("status", result)
        self.assertIn("confidence", result)

    def test_oauth_wrapper(self) -> None:
        from src.execution.validators.validators.registry_builder import _validate_oauth

        result = _validate_oauth(
            target={"url": "https://target.com/oauth/authorize"},
            context={"in_scope": True},
        )
        self.assertEqual(result["validator"], "oauth")
        self.assertEqual(result["category"], "oauth")
        self.assertIn("status", result)
        self.assertIn("confidence", result)


if __name__ == "__main__":
    unittest.main()

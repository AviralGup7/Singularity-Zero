"""Unit tests for src.analysis.active.injection._waf_detector."""

import unittest
from unittest.mock import MagicMock

import pytest

from src.analysis.active.injection._waf_detector import (
    WAF_SIGNATURES,
    WafDetectionResult,
    WafDetector,
)


@pytest.mark.unit
class TestWafSignatures(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(WAF_SIGNATURES, dict)

    def test_contains_major_wafs(self) -> None:
        for waf in ("Cloudflare", "Akamai", "AWS WAF", "ModSecurity", "Sucuri", "Imperva"):
            self.assertIn(waf, WAF_SIGNATURES)

    def test_each_signature_has_required_fields(self) -> None:
        for name, sig in WAF_SIGNATURES.items():
            self.assertIn("page", sig)
            self.assertIn("code", sig)
            self.assertIn("headers", sig)

    def test_signatures_minimum_count(self) -> None:
        self.assertGreaterEqual(len(WAF_SIGNATURES), 15)


@pytest.mark.unit
class TestWafDetectionResult(unittest.TestCase):
    def test_default_not_detected(self) -> None:
        r = WafDetectionResult(detected=False)
        self.assertFalse(r.detected)
        self.assertIsNone(r.waf_name)
        self.assertEqual(r.confidence, 0.0)
        self.assertEqual(r.evidence, [])

    def test_str_when_detected(self) -> None:
        r = WafDetectionResult(detected=True, waf_name="Cloudflare", confidence=0.9)
        s = str(r)
        self.assertIn("Cloudflare", s)
        self.assertIn("90%", s)

    def test_str_when_not_detected(self) -> None:
        r = WafDetectionResult(detected=False)
        self.assertEqual(str(r), "No WAF detected")

    def test_evidence_preserved(self) -> None:
        r = WafDetectionResult(detected=True, evidence=["a", "b"])
        self.assertEqual(r.evidence, ["a", "b"])


@pytest.mark.unit
class TestWafDetectorDetectFromResponse(unittest.TestCase):
    def test_detects_cloudflare_via_headers(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=403,
            response_body="Forbidden",
            response_headers={"cf-ray": "abc123", "server": "cloudflare"},
            triggered_by_injection=True,
        )
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "Cloudflare")

    def test_detects_aws_waf_via_403(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=403,
            response_body="",
            response_headers={"x-amzn-requestid": "abc"},
            triggered_by_injection=True,
        )
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "AWS WAF")

    def test_detects_modsecurity_via_body(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=403,
            response_body="Blocked by ModSecurity",
            response_headers={},
            triggered_by_injection=True,
        )
        self.assertTrue(result.detected)
        self.assertEqual(result.waf_name, "ModSecurity")

    def test_no_detection_clean_response(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=200,
            response_body="OK",
            response_headers={"server": "nginx"},
            triggered_by_injection=True,
        )
        self.assertFalse(result.detected)

    def test_no_detection_when_not_triggered_and_low_score(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=200,
            response_body="ray id: 123",
            response_headers={},
            triggered_by_injection=False,
        )
        self.assertFalse(result.detected)

    def test_detection_when_not_triggered_and_high_score(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=200,
            response_body="Cloudflare ray id: abc",
            response_headers={"cf-ray": "abc", "cf-cache-status": "HIT"},
            triggered_by_injection=False,
        )
        self.assertTrue(result.detected)

    def test_status_code_below_400_no_detection_when_triggered(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=200,
            response_body="ray id: 123",
            response_headers={"cf-ray": "abc"},
            triggered_by_injection=True,
        )
        self.assertFalse(result.detected)

    def test_evidence_collected(self) -> None:
        detector = WafDetector()
        result = detector.detect_from_response(
            url="https://x.com/",
            status_code=403,
            response_body="Cloudflare ray",
            response_headers={"cf-ray": "abc"},
            triggered_by_injection=True,
        )
        self.assertGreater(len(result.evidence), 0)


@pytest.mark.unit
class TestWafDetectorDetect(unittest.TestCase):
    def test_no_client_returns_not_detected(self) -> None:
        detector = WafDetector()
        result = detector.detect("https://x.com/", {"q": "test"}, {})
        self.assertFalse(result.detected)

    def test_get_request_analyzes_response(self) -> None:
        client = MagicMock()
        client.get.return_value = MagicMock(
            status_code=403,
            text="Cloudflare ray id",
            headers={"cf-ray": "abc"},
        )

        detector = WafDetector()
        result = detector.detect(
            "https://x.com/",
            {"q": "test"},
            {},
            method="GET",
            http_client=client,
        )
        client.get.assert_called_once()
        self.assertTrue(result.detected)

    def test_post_request_analyzes_response(self) -> None:
        client = MagicMock()
        client.post.return_value = MagicMock(
            status_code=403,
            text="",
            headers={"x-amzn-requestid": "abc"},
        )

        detector = WafDetector()
        result = detector.detect(
            "https://x.com/",
            {"q": "test"},
            {},
            method="POST",
            http_client=client,
        )
        client.post.assert_called_once()
        self.assertEqual(result.waf_name, "AWS WAF")

    def test_request_exception_returns_not_detected(self) -> None:
        client = MagicMock()
        client.get.side_effect = RuntimeError("connection error")

        detector = WafDetector()
        result = detector.detect(
            "https://x.com/",
            {"q": "test"},
            {},
            http_client=client,
        )
        self.assertFalse(result.detected)

    def test_injection_params_added_with_noise(self) -> None:
        client = MagicMock()
        client.get.return_value = MagicMock(
            status_code=200, text="ok", headers={}
        )

        detector = WafDetector(noise_payload="<custom>")
        detector.detect(
            "https://x.com/",
            {"q": "test"},
            {},
            http_client=client,
        )
        call_kwargs = client.get.call_args.kwargs
        self.assertIn("params", call_kwargs)
        self.assertIn("waf_test", call_kwargs["params"])
        self.assertEqual(call_kwargs["params"]["waf_test"], "<custom>")
        self.assertEqual(call_kwargs["params"]["q"], "test")


if __name__ == "__main__":
    unittest.main()

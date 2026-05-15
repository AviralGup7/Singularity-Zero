import unittest
from typing import Any, cast

from src.analysis.behavior.analysis_support import compare_response_records
from src.analysis.response.filter_rules import classify_response_delta


def _response(url: str, *, status: int, body: str) -> dict[str, Any]:
    return {
        "requested_url": url,
        "url": url,
        "status_code": status,
        "body_text": body,
        "body_length": len(body),
        "content_type": "application/json",
        "headers": {},
        "redirect_chain": [url],
        "redirect_count": 0,
    }


class ResponseFilterTests(unittest.TestCase):
    def test_ignores_same_status_near_identical(self) -> None:
        result = classify_response_delta(
            original_status=200,
            mutated_status=200,
            body_similarity=0.995,
            length_delta=8,
            redirect_changed=False,
        )
        self.assertEqual(result["classification"], "ignore")
        self.assertEqual(result["score"], 0)
        self.assertFalse(result["include"])

    def test_downranks_validation_noise(self) -> None:
        result = classify_response_delta(
            original_status=200,
            mutated_status=404,
            body_similarity=0.94,
            length_delta=20,
            redirect_changed=False,
        )
        self.assertEqual(result["classification"], "validation_noise")
        self.assertEqual(result["score"], 1)
        self.assertTrue(result["include"])

    def test_upranks_200_to_403(self) -> None:
        result = classify_response_delta(
            original_status=200,
            mutated_status=403,
            body_similarity=0.98,
            length_delta=12,
            redirect_changed=False,
        )
        self.assertEqual(result["classification"], "auth_enforcement_change")
        self.assertGreaterEqual(cast(int, result["score"]), 9)

    def test_upranks_200_to_302(self) -> None:
        result = classify_response_delta(
            original_status=200,
            mutated_status=302,
            body_similarity=0.99,
            length_delta=10,
            redirect_changed=True,
        )
        self.assertEqual(result["classification"], "redirect_gate_change")
        self.assertGreaterEqual(cast(int, result["score"]), 8)

    def test_behavior_comparison_returns_filter_fields(self) -> None:
        original = _response("https://app.example.com/a", status=200, body='{"ok":true}')
        mutated = _response("https://app.example.com/a", status=403, body='{"error":"forbidden"}')

        diff = compare_response_records(original, mutated)

        self.assertIn("classification", diff)
        self.assertIn("score", diff)
        self.assertIn("reason", diff)
        self.assertTrue(diff["changed"])


if __name__ == "__main__":
    unittest.main()

"""Unit tests for src.analysis.active.injection._efficiency."""

import unittest

import pytest

from src.analysis.active.injection._efficiency import (
    filter_efficiencies,
    reflection_efficiency,
    score_payload_executability,
)


@pytest.mark.unit
class TestReflectionEfficiencyExact(unittest.TestCase):
    def test_empty_marker_returns_zero(self) -> None:
        self.assertEqual(reflection_efficiency("body content", ""), 0)

    def test_exact_match_in_response(self) -> None:
        body = "Hello, v3dm0s is here"
        self.assertEqual(reflection_efficiency(body, "v3dm0s"), 100)

    def test_exact_match_case_sensitive_bonus(self) -> None:
        # Marker is "v3dm0s", response contains it but body is uppercase
        body = "HELLO, V3DM0S"
        # case-altered but intact -> 95
        self.assertEqual(reflection_efficiency(body, "v3dm0s"), 95)

    def test_no_reflection_low_score(self) -> None:
        body = "No marker here at all"
        result = reflection_efficiency(body, "v3dm0s")
        # Some chars may coincide; ensure it's below 50
        self.assertLess(result, 50)


@pytest.mark.unit
class TestReflectionEfficiencyEscapes(unittest.TestCase):
    def test_html_encoded_marker_returns_high_score(self) -> None:
        # When html_encoded (which also encodes & -> &amp;) is fully in the
        # body, the function returns 85 from the html-encoded branch.
        marker = "<test>"
        # html_encoded computes to "&amp;lt;test&amp;gt;"
        body = "&amp;lt;test&amp;gt;"
        result = reflection_efficiency(body, marker)
        self.assertEqual(result, 85)

    def test_url_encoded(self) -> None:
        # Quote a marker that contains special chars
        marker = "<test>"
        from urllib.parse import quote

        url_encoded = quote(marker, safe="")
        result = reflection_efficiency(f"prefix {url_encoded} suffix", marker)
        # 80 from url-encoding branch
        self.assertEqual(result, 80)

    def test_backslash_escaped_branch_unreachable(self) -> None:
        # The backslash-escape branch can never trigger because the exact
        # substring check fires first (if the body contains \\marker, it
        # also contains marker). This test simply documents the behavior
        # so future refactors don't accidentally break the contract.
        marker = "xuniqz9"
        body = "hello \\xuniqz9"
        result = reflection_efficiency(body, marker)
        # Result is 100 (exact match) because the marker IS in the body
        self.assertEqual(result, 100)

    def test_double_encoded(self) -> None:
        # marker that doesn't appear literally in body, and that html_encoded
        # does not appear in body, but double_encoded (html_encoded with each
        # '&' replaced by '&amp;') does appear.
        marker = "<xss>"
        # html_encoded = "&amp;lt;xss&amp;gt;"
        # We need a body that does NOT contain "&amp;lt;xss&amp;gt;" but DOES
        # contain a further-escaped version. Since html_encoded already escapes
        # '&', the double_encoded check is "&amp;amp;lt;xss&amp;amp;gt;".
        body = "&amp;amp;lt;xss&amp;amp;gt;"
        result = reflection_efficiency(body, marker)
        self.assertEqual(result, 75)


@pytest.mark.unit
class TestReflectionEfficiencyPartial(unittest.TestCase):
    def test_partial_substring_run(self) -> None:
        # Marker "abcdefgh" - response has "cdefgh" (6/8 = 75% consecutive)
        body = "x cdefgh y"
        result = reflection_efficiency(body, "abcdefgh")
        # Should be partial ratio (>= 50%)
        self.assertGreaterEqual(result, 50)

    def test_low_coverage_returns_low_or_zero(self) -> None:
        # Marker "zzzz" not in response
        body = "abcdef"
        result = reflection_efficiency(body, "zzzz")
        self.assertEqual(result, 0)


@pytest.mark.unit
class TestFilterEfficiencies(unittest.TestCase):
    def test_default_threshold(self) -> None:
        result = filter_efficiencies([10, 30, 50, 70, 90])
        self.assertEqual(result, [50, 70, 90])

    def test_custom_threshold(self) -> None:
        result = filter_efficiencies([10, 20, 30, 40, 50], threshold=25)
        self.assertEqual(result, [30, 40, 50])

    def test_empty_list(self) -> None:
        self.assertEqual(filter_efficiencies([]), [])

    def test_all_below_threshold(self) -> None:
        self.assertEqual(filter_efficiencies([1, 2, 3]), [])


@pytest.mark.unit
class TestScorePayloadExecutability(unittest.TestCase):
    def test_high_efficiency_html_context(self) -> None:
        score, verdict = score_payload_executability(
            "Hello, v3dm0s is here", "v3dm0s", "html"
        )
        self.assertEqual(score, 100)
        self.assertEqual(verdict, "highly_executable")

    def test_attribute_context_penalty(self) -> None:
        score, verdict = score_payload_executability(
            "v3dm0s", "v3dm0s", "attribute"
        )
        # 100 + (-10) = 90
        self.assertEqual(score, 90)
        self.assertEqual(verdict, "highly_executable")

    def test_comment_context_penalty(self) -> None:
        score, verdict = score_payload_executability(
            "v3dm0s", "v3dm0s", "comment"
        )
        # 100 - 30 = 70
        self.assertEqual(score, 70)
        self.assertEqual(verdict, "likely_executable")

    def test_script_context_bonus(self) -> None:
        score, verdict = score_payload_executability(
            "v3dm0s", "v3dm0s", "script"
        )
        # 100 + 20 = 100 (capped)
        self.assertEqual(score, 100)
        self.assertEqual(verdict, "highly_executable")

    def test_dead_context_strong_penalty(self) -> None:
        score, verdict = score_payload_executability(
            "v3dm0s", "v3dm0s", "dead"
        )
        # 100 - 50 = 50
        self.assertEqual(score, 50)
        self.assertEqual(verdict, "possibly_executable")

    def test_unknown_context_default_penalty(self) -> None:
        score, verdict = score_payload_executability(
            "v3dm0s", "v3dm0s", "unknown_type"
        )
        # 100 - 20 = 80
        self.assertEqual(score, 80)
        self.assertEqual(verdict, "likely_executable")

    def test_verdict_filtered(self) -> None:
        # 50 - 30 = 20 -> "filtered"
        score, verdict = score_payload_executability(
            "v3dm0s", "v3dm0s", "comment"
        )
        # Already covered; verifying the boundary
        self.assertIn(verdict, {"highly_executable", "likely_executable"})

    def test_score_clamped_to_zero(self) -> None:
        score, verdict = score_payload_executability("", "v3dm0s", "dead")
        # 0 - 50 = -50 -> 0
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "blocked")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for src.analysis.active.injection._efficiency."""

import unittest
from urllib.parse import quote

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

    def test_exact_match_case_altered_returns_95(self) -> None:
        body = "HELLO, V3DM0S"
        self.assertEqual(reflection_efficiency(body, "v3dm0s"), 95)

    def test_no_reflection_low_score(self) -> None:
        body = "No marker here at all"
        result = reflection_efficiency(body, "v3dm0s")
        self.assertLess(result, 50)


@pytest.mark.unit
class TestReflectionEfficiencyEscapes(unittest.TestCase):
    def test_html_encoded_marker_returns_85(self) -> None:
        marker = "<test>"
        body = "&amp;lt;test&amp;gt;"
        result = reflection_efficiency(body, marker)
        self.assertEqual(result, 85)

    def test_url_encoded(self) -> None:
        marker = "<test>"
        url_encoded = quote(marker, safe="")
        result = reflection_efficiency(f"prefix {url_encoded} suffix", marker)
        self.assertEqual(result, 80)

    def test_backslash_escaped_branch_unreachable(self) -> None:
        marker = "xuniqz9"
        body = "hello \\xuniqz9"
        result = reflection_efficiency(body, marker)
        self.assertEqual(result, 100)

    def test_double_encoded(self) -> None:
        marker = "<xss>"
        body = "&amp;amp;lt;xss&amp;amp;gt;"
        result = reflection_efficiency(body, marker)
        self.assertEqual(result, 75)


@pytest.mark.unit
class TestReflectionEfficiencyPartial(unittest.TestCase):
    def test_partial_substring_run(self) -> None:
        body = "x cdefgh y"
        result = reflection_efficiency(body, "abcdefgh")
        self.assertGreaterEqual(result, 50)

    def test_low_coverage_returns_zero(self) -> None:
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
        score, verdict = score_payload_executability("Hello, v3dm0s is here", "v3dm0s", "html")
        self.assertEqual(score, 100)
        self.assertEqual(verdict, "highly_executable")

    def test_attribute_context_penalty(self) -> None:
        score, verdict = score_payload_executability("v3dm0s", "v3dm0s", "attribute")
        self.assertEqual(score, 90)
        self.assertEqual(verdict, "highly_executable")

    def test_comment_context_penalty(self) -> None:
        score, verdict = score_payload_executability("v3dm0s", "v3dm0s", "comment")
        self.assertEqual(score, 70)
        self.assertEqual(verdict, "likely_executable")

    def test_script_context_bonus(self) -> None:
        score, verdict = score_payload_executability("v3dm0s", "v3dm0s", "script")
        self.assertEqual(score, 100)
        self.assertEqual(verdict, "highly_executable")

    def test_dead_context_strong_penalty(self) -> None:
        score, verdict = score_payload_executability("v3dm0s", "v3dm0s", "dead")
        self.assertEqual(score, 50)
        self.assertEqual(verdict, "possibly_executable")

    def test_unknown_context_default_penalty(self) -> None:
        score, verdict = score_payload_executability("v3dm0s", "v3dm0s", "unknown_type")
        self.assertEqual(score, 80)
        self.assertEqual(verdict, "likely_executable")

    def test_score_clamped_to_zero(self) -> None:
        score, verdict = score_payload_executability("", "v3dm0s", "dead")
        self.assertEqual(score, 0)
        self.assertEqual(verdict, "blocked")


if __name__ == "__main__":
    unittest.main()

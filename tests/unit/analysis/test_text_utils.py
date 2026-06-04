"""Unit tests for src.analysis.text_utils."""

import unittest

import pytest

from src.analysis.text_utils import (
    extract_key_fields,
    json_headers,
    looks_random,
    normalize_compare_text,
    redact_value,
    redacted_snippet,
    shannon_entropy,
)


@pytest.mark.unit
class TestRedactValue(unittest.TestCase):
    def test_short_value_fully_redacted(self) -> None:
        self.assertEqual(redact_value("short"), "[redacted]")

    def test_eight_chars_redacted(self) -> None:
        self.assertEqual(redact_value("12345678"), "[redacted]")

    def test_long_value_shows_first_and_last(self) -> None:
        result = redact_value("abcdefghijklmnop")
        self.assertTrue(result.startswith("abcd"))
        self.assertTrue(result.endswith("mnop"))
        self.assertIn("redacted", result)

    def test_empty_string_redacted(self) -> None:
        self.assertEqual(redact_value(""), "[redacted]")


@pytest.mark.unit
class TestRedactedSnippet(unittest.TestCase):
    def test_basic_extraction(self) -> None:
        body = "prefix" + "X" * 20 + "suffix"
        snippet = redacted_snippet(body, 7, 27, context=5)
        self.assertIn("[redacted]", snippet)

    def test_strips_newlines(self) -> None:
        body = "before\nmatch_here\nafter"
        idx = body.index("match_here")
        snippet = redacted_snippet(body, idx, idx + len("match_here"))
        self.assertNotIn("\n", snippet)

    def test_caps_at_180_chars(self) -> None:
        body = "a" * 500
        snippet = redacted_snippet(body, 200, 250, context=48)
        self.assertLessEqual(len(snippet), 180)

    def test_handles_start_at_zero(self) -> None:
        body = "abcdef"
        snippet = redacted_snippet(body, 0, 3)
        self.assertIsInstance(snippet, str)

    def test_handles_start_near_zero(self) -> None:
        body = "match" + "rest_of_body"
        snippet = redacted_snippet(body, 0, 5, context=10)
        self.assertIsInstance(snippet, str)


@pytest.mark.unit
class TestNormalizeCompareText(unittest.TestCase):
    def test_replaces_digits_with_zero(self) -> None:
        self.assertEqual(normalize_compare_text("user1234"), "user0")
        self.assertEqual(normalize_compare_text("user12.34"), "user0.0")

    def test_preserves_non_digit_chars(self) -> None:
        self.assertEqual(normalize_compare_text("abc-def"), "abc-def")

    def test_caps_at_4000_chars(self) -> None:
        text = "x" * 5000
        self.assertEqual(len(normalize_compare_text(text)), 4000)

    def test_handles_empty_string(self) -> None:
        self.assertEqual(normalize_compare_text(""), "")

    def test_handles_none_safe(self) -> None:
        self.assertEqual(normalize_compare_text(None), "")

    def test_preserves_letters(self) -> None:
        self.assertEqual(normalize_compare_text("abc"), "abc")


@pytest.mark.unit
class TestExtractKeyFields(unittest.TestCase):
    def test_extracts_simple_json_field(self) -> None:
        fields = extract_key_fields('{"username": "alice", "email": "a@b.com"}')
        self.assertIn("username", fields)
        self.assertIn("email", fields)

    def test_lowercases_field_names(self) -> None:
        fields = extract_key_fields('{"UserName": "x"}')
        self.assertIn("username", fields)

    def test_ignores_short_field_names(self) -> None:
        fields = extract_key_fields('{"a": 1, "b": 2}')
        self.assertNotIn("a", fields)
        self.assertNotIn("b", fields)

    def test_handles_empty_string(self) -> None:
        self.assertEqual(extract_key_fields(""), set())

    def test_handles_none_safe(self) -> None:
        self.assertEqual(extract_key_fields(None), set())

    def test_supports_underscore_and_dash(self) -> None:
        fields = extract_key_fields('{"first_name": 1, "x-trace-id": "abc"}')
        self.assertIn("first_name", fields)
        self.assertIn("x-trace-id", fields)

    def test_does_not_match_unquoted_keys(self) -> None:
        fields = extract_key_fields("user_name: alice")
        self.assertNotIn("user_name", fields)


@pytest.mark.unit
class TestJsonHeaders(unittest.TestCase):
    def test_format_single_header(self) -> None:
        self.assertEqual(json_headers({"X-Trace": "abc"}), "X-Trace:abc")

    def test_format_multiple_headers(self) -> None:
        result = json_headers({"A": "1", "B": "2"})
        self.assertIn("A:1", result)
        self.assertIn("B:2", result)

    def test_empty_dict(self) -> None:
        self.assertEqual(json_headers({}), "")

    def test_handles_none_safe(self) -> None:
        self.assertEqual(json_headers(None), "")


@pytest.mark.unit
class TestShannonEntropy(unittest.TestCase):
    def test_empty_string_zero(self) -> None:
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char_zero(self) -> None:
        self.assertEqual(shannon_entropy("a"), 0.0)

    def test_repeated_char_zero(self) -> None:
        self.assertEqual(shannon_entropy("aaaaaaaa"), 0.0)

    def test_two_equally_distributed_chars(self) -> None:
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0, places=5)

    def test_four_equally_distributed_chars(self) -> None:
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0, places=5)

    def test_returns_non_negative(self) -> None:
        self.assertGreaterEqual(shannon_entropy("Hello, World!"), 0.0)

    def test_random_string_higher_entropy(self) -> None:
        self.assertGreater(shannon_entropy("aB3$xZ9!qW1#"), shannon_entropy("aaaaaaaa"))


@pytest.mark.unit
class TestLooksRandom(unittest.TestCase):
    def test_empty_string_not_random(self) -> None:
        self.assertFalse(looks_random(""))

    def test_short_string_not_random(self) -> None:
        self.assertFalse(looks_random("abc"))

    def test_aaaaaaa_not_random(self) -> None:
        self.assertFalse(looks_random("aaaaaaa"))

    def test_high_entropy_with_mix_returns_true(self) -> None:
        self.assertTrue(looks_random("aB3xZ9qW1nM4pQ7"))

    def test_no_digits_returns_false_or_bool(self) -> None:
        result = looks_random("AbCdEfGhIjKlMnOp")
        self.assertIsInstance(result, bool)

    def test_returns_bool(self) -> None:
        self.assertIsInstance(looks_random("test123"), bool)


if __name__ == "__main__":
    unittest.main()

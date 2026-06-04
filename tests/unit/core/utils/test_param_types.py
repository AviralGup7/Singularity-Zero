"""Unit tests for src.core.utils.param_types."""

import unittest

import pytest

from src.core.utils.param_types import (
    IDOR_PARAM_NAMES,
    REDIRECT_PARAM_NAMES,
    SSRF_PARAM_NAMES,
    TOKEN_PARAM_NAMES,
    UUID_RE,
    decode_candidate_value,
)


@pytest.mark.unit
class TestParameterNameSets(unittest.TestCase):
    def test_redirect_param_names_contains_common_keys(self) -> None:
        for key in ("redirect", "next", "return", "callback", "url"):
            self.assertIn(key, REDIRECT_PARAM_NAMES)

    def test_idor_param_names_contains_common_keys(self) -> None:
        for key in ("id", "user_id", "uuid", "account_id"):
            self.assertIn(key, IDOR_PARAM_NAMES)

    def test_ssrf_param_names_contains_common_keys(self) -> None:
        for key in ("url", "uri", "callback", "webhook", "host"):
            self.assertIn(key, SSRF_PARAM_NAMES)

    def test_token_param_names_contains_jwt_aliases(self) -> None:
        for key in ("token", "access_token", "jwt", "api_key"):
            self.assertIn(key, TOKEN_PARAM_NAMES)

    def test_all_param_sets_are_lowercased(self) -> None:
        for s in (REDIRECT_PARAM_NAMES, IDOR_PARAM_NAMES, SSRF_PARAM_NAMES, TOKEN_PARAM_NAMES):
            for name in s:
                self.assertEqual(name, name.lower())

    def test_param_sets_are_immutable_sets(self) -> None:
        self.assertIsInstance(REDIRECT_PARAM_NAMES, set)
        self.assertIsInstance(IDOR_PARAM_NAMES, set)
        self.assertIsInstance(SSRF_PARAM_NAMES, set)
        self.assertIsInstance(TOKEN_PARAM_NAMES, set)

    def test_sets_have_no_overlap_with_specific_keys(self) -> None:
        self.assertNotIn("url", TOKEN_PARAM_NAMES)
        self.assertNotIn("user_id", REDIRECT_PARAM_NAMES)


@pytest.mark.unit
class TestUuidRegex(unittest.TestCase):
    def test_matches_v4_uuid(self) -> None:
        text = "abc 550e8400-e29b-41d4-a716-446655440000 xyz"
        self.assertIsNotNone(UUID_RE.search(text))

    def test_matches_uppercase_uuid(self) -> None:
        text = "550E8400-E29B-41D4-A716-446655440000"
        self.assertIsNotNone(UUID_RE.search(text))

    def test_does_not_match_short_string(self) -> None:
        self.assertIsNone(UUID_RE.search("abc123"))

    def test_does_not_match_invalid_version(self) -> None:
        invalid = "550e8400-e29b-71d4-a716-446655440000"
        self.assertIsNone(UUID_RE.search(invalid))

    def test_extracts_uuid_from_url(self) -> None:
        url = "https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile"
        match = UUID_RE.search(url)
        self.assertIsNotNone(match)
        assert match is not None
        self.assertEqual(match.group(0).lower(), "550e8400-e29b-41d4-a716-446655440000")

    def test_does_not_match_word_boundary_violation(self) -> None:
        text = "X550e8400-e29b-41d4-a716-446655440000X"
        self.assertIsNone(UUID_RE.search(text))

    def test_matches_v1_uuid(self) -> None:
        text = "00000000-0000-1000-8000-000000000000"
        self.assertIsNotNone(UUID_RE.search(text))


@pytest.mark.unit
class TestDecodeCandidateValue(unittest.TestCase):
    def test_returns_empty_for_empty_input(self) -> None:
        self.assertEqual(decode_candidate_value(""), "")

    def test_returns_empty_for_none(self) -> None:
        self.assertEqual(decode_candidate_value(None), "")  # type: ignore[arg-type]

    def test_decodes_single_url_encoding(self) -> None:
        self.assertEqual(decode_candidate_value("hello%20world"), "hello world")

    def test_decodes_double_encoding(self) -> None:
        encoded = "hello%2520world"
        self.assertEqual(decode_candidate_value(encoded), "hello world")

    def test_decodes_triple_encoding(self) -> None:
        encoded = "hello%252520world"
        self.assertEqual(decode_candidate_value(encoded), "hello world")

    def test_strips_whitespace(self) -> None:
        self.assertEqual(decode_candidate_value("  test  "), "test")

    def test_handles_max_rounds_parameter(self) -> None:
        encoded = "a%2520b"
        result = decode_candidate_value(encoded, max_rounds=1)
        self.assertEqual(result, "a%20b")

    def test_max_rounds_zero_returns_input(self) -> None:
        encoded = "hello%20world"
        result = decode_candidate_value(encoded, max_rounds=0)
        self.assertEqual(result, "hello%20world")

    def test_returns_unchanged_when_not_encoded(self) -> None:
        self.assertEqual(decode_candidate_value("plaintext"), "plaintext")

    def test_handles_invalid_percent_sequences(self) -> None:
        result = decode_candidate_value("test%ZZ")
        self.assertEqual(result, "test%ZZ")

    def test_handles_unicode_value(self) -> None:
        self.assertEqual(decode_candidate_value("héllo"), "héllo")

    def test_handles_numeric_input_coerced_to_string(self) -> None:
        result = decode_candidate_value(123)  # type: ignore[arg-type]
        self.assertEqual(result, "123")


if __name__ == "__main__":
    unittest.main()

"""Unit tests for src.core.utils.shared (URL/scope normalization)."""

import unittest

import pytest

from src.core.utils.shared import (
    normalize_scope_entry,
    normalize_url,
    parse_plain_lines,
)


@pytest.mark.unit
class TestNormalizeScopeEntry(unittest.TestCase):
    def test_strips_wildcard_prefix(self) -> None:
        self.assertEqual(normalize_scope_entry("*.example.com"), "example.com")

    def test_returns_unchanged_when_no_wildcard(self) -> None:
        self.assertEqual(normalize_scope_entry("example.com"), "example.com")

    def test_only_strips_leading_wildcard(self) -> None:
        # Multiple wildcards only the prefix is stripped
        self.assertEqual(normalize_scope_entry("*.sub.example.com"), "sub.example.com")

    def test_empty_string(self) -> None:
        self.assertEqual(normalize_scope_entry(""), "")

    def test_does_not_strip_middle_wildcard(self) -> None:
        self.assertEqual(normalize_scope_entry("sub.*.example.com"), "sub.*.example.com")


@pytest.mark.unit
class TestNormalizeUrl(unittest.TestCase):
    def test_empty_string_returns_empty(self) -> None:
        self.assertEqual(normalize_url(""), "")

    def test_lowercases_scheme(self) -> None:
        self.assertEqual(normalize_url("HTTPS://example.com"), "https://example.com")

    def test_lowercases_netloc(self) -> None:
        self.assertEqual(normalize_url("https://Example.COM/path"), "https://example.com/path")

    def test_strips_default_https_port(self) -> None:
        self.assertEqual(normalize_url("https://example.com:443/"), "https://example.com")

    def test_strips_default_http_port(self) -> None:
        self.assertEqual(normalize_url("http://example.com:80/"), "http://example.com")

    def test_preserves_non_default_port(self) -> None:
        result = normalize_url("https://example.com:8443/")
        self.assertIn("8443", result)

    def test_sorts_query_parameters(self) -> None:
        url = "https://example.com/api?z=1&a=2&m=3"
        result = normalize_url(url)
        self.assertEqual(result, "https://example.com/api?a=2&m=3&z=1")

    def test_keeps_blank_values(self) -> None:
        url = "https://example.com/api?empty=&other=value"
        result = normalize_url(url)
        self.assertIn("empty=", result)

    def test_resolves_path_traversal(self) -> None:
        url = "https://example.com/api/v1/../v2/users"
        result = normalize_url(url)
        self.assertNotIn("..", result)

    def test_adds_https_when_no_scheme(self) -> None:
        result = normalize_url("example.com/path")
        self.assertTrue(result.startswith("https://"))

    def test_handles_whitespace(self) -> None:
        result = normalize_url("  https://example.com  ")
        self.assertEqual(result, "https://example.com")


@pytest.mark.unit
class TestParsePlainLines(unittest.TestCase):
    def test_empty_text_returns_empty_set(self) -> None:
        self.assertEqual(parse_plain_lines(""), set())

    def test_single_line_added(self) -> None:
        result = parse_plain_lines("example.com")
        self.assertEqual(result, {"example.com"})

    def test_deduplicates_lines(self) -> None:
        result = parse_plain_lines("example.com\nexample.com\nEXAMPLE.COM")
        self.assertEqual(len(result), 1)

    def test_normalizes_urls(self) -> None:
        result = parse_plain_lines("https://EXAMPLE.com:443/")
        self.assertIn("https://example.com", result)

    def test_normalizes_paths_as_urls(self) -> None:
        result = parse_plain_lines("/api/v1")
        # path-only with slash routed through URL normalization
        self.assertEqual(len(result), 1)

    def test_lowercases_non_url_entries(self) -> None:
        result = parse_plain_lines("EXAMPLE.COM")
        self.assertEqual(result, {"example.com"})

    def test_multiple_lines(self) -> None:
        result = parse_plain_lines("a.com\nb.com\nc.com")
        self.assertEqual(result, {"a.com", "b.com", "c.com"})

    def test_skips_empty_lines(self) -> None:
        # Empty lines normalize to empty strings which are filtered
        result = parse_plain_lines("\n\nexample.com\n\n")
        self.assertEqual(result, {"example.com"})


if __name__ == "__main__":
    unittest.main()

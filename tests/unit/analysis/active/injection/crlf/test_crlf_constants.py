"""Unit tests for src.analysis.active.injection.crlf._crlf_constants."""

import unittest

import pytest

from src.analysis.active.injection.crlf._crlf_constants import (
    CRLF_APPEND_SUFFIXES,
    CRLF_ESCAPE_SEQUENCES,
    CRLF_PROBE_PAYLOADS,
)


@pytest.mark.unit
class TestCrlfAppendSuffixes(unittest.TestCase):
    def test_is_list(self) -> None:
        self.assertIsInstance(CRLF_APPEND_SUFFIXES, list)

    def test_contains_empty_string(self) -> None:
        self.assertIn("", CRLF_APPEND_SUFFIXES)

    def test_contains_crlf_string(self) -> None:
        self.assertIn("crlf", CRLF_APPEND_SUFFIXES)

    def test_contains_hash(self) -> None:
        self.assertIn("#", CRLF_APPEND_SUFFIXES)

    def test_contains_semicolon(self) -> None:
        self.assertIn(";", CRLF_APPEND_SUFFIXES)

    def test_minimum_count(self) -> None:
        self.assertGreaterEqual(len(CRLF_APPEND_SUFFIXES), 4)

    def test_all_strings(self) -> None:
        for s in CRLF_APPEND_SUFFIXES:
            self.assertIsInstance(s, str)


@pytest.mark.unit
class TestCrlfEscapeSequences(unittest.TestCase):
    def test_is_list(self) -> None:
        self.assertIsInstance(CRLF_ESCAPE_SEQUENCES, list)

    def test_contains_raw_crlf(self) -> None:
        keys = [next(iter(d.keys())) for d in CRLF_ESCAPE_SEQUENCES]
        self.assertIn("crlf_raw", keys)

    def test_contains_uppercase_crlf(self) -> None:
        keys = [next(iter(d.keys())) for d in CRLF_ESCAPE_SEQUENCES]
        self.assertIn("crlf_upper", keys)

    def test_contains_double_encoded(self) -> None:
        keys = [next(iter(d.keys())) for d in CRLF_ESCAPE_SEQUENCES]
        self.assertIn("crlf_double", keys)

    def test_contains_n_only(self) -> None:
        keys = [next(iter(d.keys())) for d in CRLF_ESCAPE_SEQUENCES]
        self.assertIn("crlf_n_only", keys)

    def test_contains_unicode_escapes(self) -> None:
        keys = [next(iter(d.keys())) for d in CRLF_ESCAPE_SEQUENCES]
        self.assertIn("crlf_unicode_n", keys)
        self.assertIn("crlf_unicode_r", keys)

    def test_contains_utf8_escapes(self) -> None:
        keys = [next(iter(d.keys())) for d in CRLF_ESCAPE_SEQUENCES]
        self.assertIn("crlf_utf8_n", keys)
        self.assertIn("crlf_utf8_r", keys)

    def test_each_entry_is_single_key_dict(self) -> None:
        for entry in CRLF_ESCAPE_SEQUENCES:
            self.assertIsInstance(entry, dict)
            self.assertEqual(len(entry), 1)

    def test_values_contain_percent_encoded(self) -> None:
        for entry in CRLF_ESCAPE_SEQUENCES:
            value = next(iter(entry.values()))
            self.assertIn("%", value)


@pytest.mark.unit
class TestCrlfProbePayloads(unittest.TestCase):
    def test_is_list(self) -> None:
        self.assertIsInstance(CRLF_PROBE_PAYLOADS, list)

    def test_minimum_count(self) -> None:
        self.assertGreaterEqual(len(CRLF_PROBE_PAYLOADS), 20)

    def test_each_entry_has_name_and_template(self) -> None:
        for entry in CRLF_PROBE_PAYLOADS:
            self.assertIn("name", entry)
            self.assertIn("template", entry)

    def test_contains_set_cookie(self) -> None:
        names = [p["name"] for p in CRLF_PROBE_PAYLOADS]
        self.assertIn("set_cookie", names)

    def test_contains_xss_payloads(self) -> None:
        names = [p["name"] for p in CRLF_PROBE_PAYLOADS]
        self.assertTrue(any("xss" in n for n in names))

    def test_templates_reference_crlf_placeholder(self) -> None:
        literal_only = {
            "location_redirect",
            "location_with_tab",
            "double_location",
        }
        for entry in CRLF_PROBE_PAYLOADS:
            template = entry["template"]
            if entry["name"] not in literal_only:
                self.assertIn("{crlf}", template)

    def test_templates_reference_token(self) -> None:
        no_token = {
            "status_code_inject",
            "location_redirect",
            "location_with_tab",
            "double_location",
            "content_type_override",
        }
        for entry in CRLF_PROBE_PAYLOADS:
            template = entry["template"]
            if entry["name"] not in no_token:
                self.assertIn("{token}", template)


if __name__ == "__main__":
    unittest.main()

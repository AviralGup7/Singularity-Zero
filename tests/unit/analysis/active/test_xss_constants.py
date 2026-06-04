"""Unit tests for src.analysis.active.xss_constants."""

import unittest

import pytest

from src.analysis.active.xss_constants import (
    EVENT_HANDLERS,
    HANDLER_FILLINGS,
    INJECTION_TAGS,
    JS_FILLINGS,
    JS_FUNCTIONS,
    LINE_FILLINGS,
    NON_EXECUTABLE_TAGS,
    SPACE_ALTERNATIVES,
    WAF_EVASION_PATTERNS,
    XSS_DANGEROUS_VALUE_RE,
    XSS_FIELD_RE,
    XSS_PROBE_PREFIX,
    XSS_PROBE_SUFFIX,
    XSS_REFLECTION_CANDIDATE_NAMES,
    XSS_SKIP_PARAM_NAMES,
)


@pytest.mark.unit
class TestXssProbeMarkers(unittest.TestCase):
    def test_prefix(self) -> None:
        self.assertEqual(XSS_PROBE_PREFIX, "xssprobe")

    def test_suffix(self) -> None:
        self.assertEqual(XSS_PROBE_SUFFIX, "123")


@pytest.mark.unit
class TestXssDangerousValueRegex(unittest.TestCase):
    def test_matches_script_tag(self) -> None:
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("<script>alert(1)</script>"))

    def test_matches_javascript_uri(self) -> None:
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("javascript:alert(1)"))

    def test_matches_event_handler(self) -> None:
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("onerror=alert(1)"))

    def test_matches_svg(self) -> None:
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("<svg onload=alert(1)>"))

    def test_matches_img(self) -> None:
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("<img src=x>"))

    def test_matches_iframe(self) -> None:
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("<iframe src=evil>"))

    def test_case_insensitive(self) -> None:
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("<SCRIPT>"))
        self.assertIsNotNone(XSS_DANGEROUS_VALUE_RE.search("JaVaScRiPt:"))

    def test_does_not_match_clean_text(self) -> None:
        self.assertIsNone(XSS_DANGEROUS_VALUE_RE.search("Hello, world!"))


@pytest.mark.unit
class TestXssFieldRegex(unittest.TestCase):
    def test_matches_field_with_script(self) -> None:
        text = '"bio": "<script>alert(1)</script>"'
        m = XSS_FIELD_RE.search(text)
        self.assertIsNotNone(m)
        if m:
            self.assertEqual(m.group("field"), "bio")

    def test_does_not_match_when_no_xss_payload(self) -> None:
        self.assertIsNone(XSS_FIELD_RE.search('"username": "alice"'))


@pytest.mark.unit
class TestXssReflectionCandidateNames(unittest.TestCase):
    def test_is_set(self) -> None:
        self.assertIsInstance(XSS_REFLECTION_CANDIDATE_NAMES, set)

    def test_contains_common_reflection_params(self) -> None:
        for name in ("q", "query", "search", "s", "name", "redirect", "url", "callback"):
            self.assertIn(name, XSS_REFLECTION_CANDIDATE_NAMES)

    def test_does_not_contain_auth_params(self) -> None:
        for name in ("token", "auth", "session"):
            self.assertNotIn(name, XSS_REFLECTION_CANDIDATE_NAMES)

    def test_minimum_param_count(self) -> None:
        self.assertGreaterEqual(len(XSS_REFLECTION_CANDIDATE_NAMES), 30)


@pytest.mark.unit
class TestXssSkipParamNames(unittest.TestCase):
    def test_contains_auth_params(self) -> None:
        for name in ("token", "session", "jwt", "auth", "api_key", "csrf"):
            self.assertIn(name, XSS_SKIP_PARAM_NAMES)

    def test_contains_tracking_params(self) -> None:
        for name in ("utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid"):
            self.assertIn(name, XSS_SKIP_PARAM_NAMES)

    def test_does_not_contain_reflection_params(self) -> None:
        for name in ("q", "search", "redirect", "url"):
            self.assertNotIn(name, XSS_SKIP_PARAM_NAMES)


@pytest.mark.unit
class TestNonExecutableTags(unittest.TestCase):
    def test_is_frozenset(self) -> None:
        self.assertIsInstance(NON_EXECUTABLE_TAGS, frozenset)

    def test_contains_iframe(self) -> None:
        self.assertIn("iframe", NON_EXECUTABLE_TAGS)

    def test_contains_textarea(self) -> None:
        self.assertIn("textarea", NON_EXECUTABLE_TAGS)

    def test_contains_template(self) -> None:
        self.assertIn("template", NON_EXECUTABLE_TAGS)


@pytest.mark.unit
class TestFillingConstants(unittest.TestCase):
    def test_js_fillings_contains_semicolon(self) -> None:
        self.assertIn(";", JS_FILLINGS)

    def test_line_fillings_starts_with_empty(self) -> None:
        self.assertEqual(LINE_FILLINGS[0], "")

    def test_handler_fillings_contains_tab(self) -> None:
        self.assertIn("%09", HANDLER_FILLINGS)

    def test_space_alternatives_contains_tab(self) -> None:
        self.assertIn("%09", SPACE_ALTERNATIVES)


@pytest.mark.unit
class TestWafEvasionPatterns(unittest.TestCase):
    def test_is_tuple(self) -> None:
        self.assertIsInstance(WAF_EVASION_PATTERNS, tuple)

    def test_non_empty(self) -> None:
        self.assertGreater(len(WAF_EVASION_PATTERNS), 0)

    def test_all_patterns_are_strings(self) -> None:
        for p in WAF_EVASION_PATTERNS:
            self.assertIsInstance(p, str)

    def test_contains_html_payloads(self) -> None:
        combined = " ".join(WAF_EVASION_PATTERNS)
        self.assertIn("confirm", combined)


@pytest.mark.unit
class TestEventHandlersAndTags(unittest.TestCase):
    def test_event_handlers_is_dict(self) -> None:
        self.assertIsInstance(EVENT_HANDLERS, dict)

    def test_ontoggle_maps_to_details(self) -> None:
        self.assertIn("details", EVENT_HANDLERS["ontoggle"])

    def test_injection_tags_is_tuple(self) -> None:
        self.assertIsInstance(INJECTION_TAGS, tuple)

    def test_injection_tags_contains_html(self) -> None:
        self.assertIn("html", INJECTION_TAGS)


@pytest.mark.unit
class TestJsFunctions(unittest.TestCase):
    def test_is_tuple(self) -> None:
        self.assertIsInstance(JS_FUNCTIONS, tuple)

    def test_contains_confirm(self) -> None:
        self.assertTrue(any("confirm" in f for f in JS_FUNCTIONS))

    def test_contains_prompt(self) -> None:
        self.assertTrue(any("prompt" in f for f in JS_FUNCTIONS))


if __name__ == "__main__":
    unittest.main()

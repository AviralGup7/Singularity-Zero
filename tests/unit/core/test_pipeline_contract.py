import unittest

from src.core.contracts.pipeline import (
    OUTPUT_JSON_SCHEMA,
    TIMEOUT_DEFAULTS,
    VALIDATION_RESULT_SCHEMA_VERSION,
    VALIDATION_RUNTIME_SCHEMA_VERSION,
    dedup_digest,
    dedup_key,
    scope_match,
    validation_finding_fixture,
    validation_runtime_fixture,
)


class PipelineContractTests(unittest.TestCase):
    def test_validation_schema_versions_match_contract(self) -> None:
        self.assertEqual(
            VALIDATION_RESULT_SCHEMA_VERSION,
            OUTPUT_JSON_SCHEMA["validation_result"]["schema_version"],
        )
        self.assertEqual(
            VALIDATION_RUNTIME_SCHEMA_VERSION,
            OUTPUT_JSON_SCHEMA["validation_runtime"]["schema_version"],
        )

    def test_scope_match_supports_exact_and_host_family(self) -> None:
        self.assertEqual(
            scope_match("https://api.example.com/v1", {"api.example.com"}), (True, "exact_match")
        )
        self.assertEqual(
            scope_match("https://foo.example.com/v1", {"api.example.com"}),
            (True, "host_family_match"),
        )
        self.assertEqual(
            scope_match("https://other.net", {"api.example.com"}), (False, "outside_scope")
        )

    def test_same_host_family_supports_multi_part_tld(self) -> None:
        from src.core.contracts.pipeline import same_host_family

        self.assertFalse(same_host_family("target.co.uk", "evil.co.uk"))
        self.assertTrue(same_host_family("sub.target.co.uk", "target.co.uk"))
        self.assertFalse(same_host_family("target.com.au", "evil.com.au"))
        self.assertTrue(same_host_family("sub.target.com.au", "target.com.au"))

    def test_dedup_helpers_are_deterministic(self) -> None:
        self.assertEqual(dedup_key("a", 1, "b"), "a|1|b")
        self.assertEqual(dedup_key("a|b", "c"), "a\\|b|c")
        self.assertEqual(dedup_digest("a", 1, "b"), dedup_digest("a", 1, "b"))

    def test_contract_fixtures_produce_valid_shapes(self) -> None:
        finding = validation_finding_fixture()
        runtime_payload = validation_runtime_fixture()

        self.assertEqual(finding["schema_version"], VALIDATION_RESULT_SCHEMA_VERSION)
        self.assertEqual(runtime_payload["schema_version"], VALIDATION_RUNTIME_SCHEMA_VERSION)
        self.assertIn("validation_actions", finding)
        self.assertEqual(
            finding["http"]["timeout_seconds"], TIMEOUT_DEFAULTS["http_request_seconds"]
        )
        self.assertIn("results", runtime_payload)
        self.assertIn("settings", runtime_payload)

    def test_char_overlap_score_bounds(self) -> None:
        from src.analysis.active.xss_context_engine import _char_overlap_score

        self.assertEqual(_char_overlap_score("abc", "abc"), 100)
        self.assertEqual(_char_overlap_score("", "abc"), 0)

    def test_pop_matching_no_in_place_warn(self) -> None:
        from src.analysis.active.xss_context_engine import _pop_matching

        stack = ["{", "(", "[", ")"]
        _pop_matching(stack, "(")
        self.assertEqual(stack, ["{", "[", ")"])
        _pop_matching(stack, "nonexistent")
        self.assertEqual(stack, ["{", "[", ")"])

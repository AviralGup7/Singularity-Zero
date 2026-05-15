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

    def test_dedup_helpers_are_deterministic(self) -> None:
        self.assertEqual(dedup_key("a", 1, "b"), "a|1|b")
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

import unittest

from src.analysis.intelligence.findings_dedup import deduplicate_findings
from src.core.contracts.finding_lifecycle import apply_lifecycle
from src.core.contracts.schema_validator import (
    SchemaValidationError,
    validate_analysis_payload,
    validate_decision_payload,
    validate_detection_payload,
    validate_execution_payload,
    validate_recon_payload,
)


class PipelineContractEnforcementTests(unittest.TestCase):
    def test_recon_payload_requires_absolute_urls(self) -> None:
        with self.assertRaises(SchemaValidationError):
            validate_recon_payload({"urls": ["/relative"], "live_hosts": []})

        validate_recon_payload(
            {"urls": ["https://example.com/path"], "live_hosts": ["https://example.com"]}
        )

    def test_detection_payload_requires_list_buckets(self) -> None:
        with self.assertRaises(SchemaValidationError):
            validate_detection_payload({"token_leak_detector": {"url": "https://example.com"}})

        validate_detection_payload({"token_leak_detector": [{"url": "https://example.com"}]})

    def test_analysis_decision_execution_payload_shapes(self) -> None:
        validate_analysis_payload({"findings": [{"url": "https://example.com", "severity": "low"}]})
        validate_decision_payload(
            {"findings": [{"url": "https://example.com", "decision": "KEEP"}]}
        )
        validate_execution_payload({"results": {"idor_validation": []}, "errors": []})

    def test_finding_lifecycle_state_progression(self) -> None:
        normalized = apply_lifecycle(
            [
                {
                    "url": "https://a.example.com",
                    "severity": "medium",
                    "validation_state": "passive_only",
                },
                {
                    "url": "https://b.example.com",
                    "validation_state": "active_ready",
                    "exploit_verified": True,
                },
                {"url": "https://c.example.com", "severity": "high", "decision": "KEEP"},
            ]
        )
        states = [item["lifecycle_state"] for item in normalized]
        self.assertEqual(states[0], "detected")
        self.assertEqual(states[1], "exploitable")
        # KEEP + high severity infers reportable; transition from None allows direct jump
        self.assertEqual(states[2], "reportable")

    def test_lifecycle_infers_from_evidence_validation_state(self) -> None:
        normalized = apply_lifecycle(
            [
                {
                    "url": "https://validator.example.com/profile",
                    "severity": "medium",
                    "evidence": {"validation_state": "active_ready"},
                }
            ]
        )
        self.assertEqual(normalized[0]["lifecycle_state"], "exploitable")

    def test_dedup_preserves_validation_context_for_lifecycle(self) -> None:
        findings = [
            {
                "module": "passive_detector",
                "category": "idor",
                "title": "Potential object reference exposure",
                "url": "https://api.example.com/users/1",
                "severity": "medium",
                "score": 90,
                "confidence": 0.61,
                "evidence": {"signals": ["passive_signal"]},
            },
            {
                "module": "idor_validation",
                "category": "idor",
                "title": "Potential object reference exposure",
                "url": "https://api.example.com/users/1",
                "severity": "medium",
                "score": 40,
                "confidence": 0.88,
                "evidence": {
                    "signals": ["active_validation"],
                    "validation_state": "active_ready",
                    "confirmed": True,
                },
            },
        ]

        deduped = deduplicate_findings(findings)

        self.assertEqual(len(deduped), 1)
        evidence = deduped[0].get("evidence", {})
        self.assertEqual(evidence.get("validation_state"), "active_ready")
        self.assertTrue(evidence.get("confirmed"))
        self.assertIn("active_validation", evidence.get("signals", []))
        self.assertIn("passive_signal", evidence.get("signals", []))

        normalized = apply_lifecycle(deduped)
        self.assertEqual(normalized[0]["lifecycle_state"], "exploitable")


if __name__ == "__main__":
    unittest.main()

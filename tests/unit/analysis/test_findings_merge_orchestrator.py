import unittest

from src.analysis.intelligence.findings.intelligence_findings._merge_orchestrator import (
    _dedup_cross_module,
    _dedup_evidence_similarity,
)


class MergeOrchestratorDedupTests(unittest.TestCase):
    def test_cross_module_dedup_preserves_validation_context(self) -> None:
        findings = [
            {
                "module": "passive_detector",
                "category": "idor",
                "title": "Potential object reference exposure",
                "url": "https://api.example.com/users/1",
                "score": 90,
                "confidence": 0.61,
                "evidence": {"signals": ["passive_signal"]},
            },
            {
                "module": "idor_validation",
                "category": "idor",
                "title": "Potential object reference exposure",
                "url": "https://api.example.com/users/1",
                "score": 40,
                "confidence": 0.88,
                "verified": True,
                "evidence": {
                    "signals": ["active_validation"],
                    "validation_state": "active_ready",
                    "confirmed": True,
                },
            },
        ]

        merged = _dedup_cross_module(findings)

        self.assertEqual(len(merged), 1)
        evidence = merged[0].get("evidence", {})
        self.assertEqual(evidence.get("validation_state"), "active_ready")
        self.assertTrue(merged[0].get("verified"))
        self.assertTrue(evidence.get("confirmed"))
        self.assertIn("active_validation", evidence.get("signals", []))
        self.assertIn("passive_signal", evidence.get("signals", []))

    def test_evidence_similarity_dedup_keeps_verified_context(self) -> None:
        findings = [
            {
                "module": "passive_detector",
                "category": "ssrf",
                "title": "Potential SSRF sink parameter",
                "url": "https://api.example.com/search?q=1",
                "score": 70,
                "confidence": 0.55,
                "evidence": {"signals": ["passive_signal"]},
            },
            {
                "module": "ssrf_validation",
                "category": "ssrf",
                "title": "Potential SSRF sink parameter",
                "url": "https://api.example.com/search?q=2",
                "score": 60,
                "confidence": 0.9,
                "exploit_verified": True,
                "evidence": {
                    "signals": ["active_probe"],
                    "validation_state": "confirmed",
                    "confirmed": True,
                },
            },
        ]

        deduped = _dedup_evidence_similarity(findings, similarity_threshold=0.5)

        self.assertEqual(len(deduped), 1)
        evidence = deduped[0].get("evidence", {})
        self.assertEqual(evidence.get("validation_state"), "confirmed")
        self.assertTrue(deduped[0].get("exploit_verified"))
        self.assertTrue(evidence.get("confirmed"))
        self.assertIn("active_probe", evidence.get("signals", []))
        self.assertIn("passive_signal", evidence.get("signals", []))


if __name__ == "__main__":
    unittest.main()

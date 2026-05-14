import unittest

from src.pipeline.services.pipeline_helpers import (
    extract_feedback_urls,
    finding_identity,
)


class IterativeScanningTests(unittest.TestCase):
    def test_finding_identity_is_stable(self) -> None:
        finding = {
            "category": "Access_Control",
            "url": "https://api.example.com/users/1",
            "title": "Potential IDOR",
        }
        identity = finding_identity(finding)
        self.assertEqual(identity, "access_control|https://api.example.com/users/1|potential idor")

    def test_extract_feedback_urls_prefers_new_findings_and_absolute_urls(self) -> None:
        finding = {
            "category": "idor",
            "url": "https://api.example.com/users/2",
            "title": "Potential IDOR",
            "evidence": {
                "mutated_url": "https://api.example.com/users/3",
                "final_url": "/relative-only",
            },
        }
        new_keys = {finding_identity(finding)}
        urls = extract_feedback_urls([finding], new_keys)
        self.assertIn("https://api.example.com/users/2", urls)
        self.assertIn("https://api.example.com/users/3", urls)
        self.assertNotIn("/relative-only", urls)


if __name__ == "__main__":
    unittest.main()

import unittest

from src.analysis.bug_bounty.dedup import FindingDedup


class TestStructuralFindingDedup(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.dedup = FindingDedup(self.tmp.name)

    def test_parameterized_vuln_with_different_payloads_coalesces_to_same_fingerprint(self) -> None:
        # Same XSS on /search with different query payloads
        finding_payload_1 = {
            "tool": "nuclei",
            "vuln_type": "Reflected XSS",
            "target_url": "https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "param": "q",
            "response_signature": "200_html_alert",
        }
        finding_payload_2 = {
            "tool": "nuclei",
            "vuln_type": "Reflected XSS",
            "target_url": "https://example.com/search?q=%22%3E%3Cimg+src=x+onerror=alert(2)%3E",
            "param": "q",
            "response_signature": "200_html_alert",
        }

        fp1 = self.dedup.fingerprint_finding(finding_payload_1)
        fp2 = self.dedup.fingerprint_finding(finding_payload_2)
        # Must produce identical structural fingerprint!
        self.assertEqual(fp1, fp2)

    def test_distinct_injection_parameters_produce_distinct_fingerprints(self) -> None:
        # Same endpoint, but one SQLi is in ?id=1 and another is in ?category=books
        finding_param_id = {
            "tool": "sqlmap",
            "vuln_type": "SQL Injection",
            "target_url": "https://example.com/api/user?id=1",
            "param": "id",
        }
        finding_param_cat = {
            "tool": "sqlmap",
            "vuln_type": "SQL Injection",
            "target_url": "https://example.com/api/user?category=books",
            "param": "category",
        }

        fp_id = self.dedup.fingerprint_finding(finding_param_id)
        fp_cat = self.dedup.fingerprint_finding(finding_param_cat)
        # Must be different fingerprints!
        self.assertNotEqual(fp_id, fp_cat)


if __name__ == "__main__":
    unittest.main()

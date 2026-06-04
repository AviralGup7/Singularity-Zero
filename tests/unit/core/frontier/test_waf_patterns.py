"""Unit tests for src.core.frontier.waf_patterns (CDN_WAF_PATTERNS fingerprints)."""

import unittest

import pytest

from src.core.frontier.waf_patterns import CDN_WAF_PATTERNS


@pytest.mark.unit
class TestCdnWafPatternsStructure(unittest.TestCase):
    def test_is_dict(self) -> None:
        self.assertIsInstance(CDN_WAF_PATTERNS, dict)

    def test_pattern_keys_are_strings(self) -> None:
        for key in CDN_WAF_PATTERNS:
            self.assertIsInstance(key, str)

    def test_each_entry_has_three_keys(self) -> None:
        for name, data in CDN_WAF_PATTERNS.items():
            self.assertIn("headers", data, f"{name} missing 'headers'")
            self.assertIn("cookies", data, f"{name} missing 'cookies'")
            self.assertIn("body", data, f"{name} missing 'body'")

    def test_each_list_field_is_a_list(self) -> None:
        for name, data in CDN_WAF_PATTERNS.items():
            self.assertIsInstance(data["headers"], list)
            self.assertIsInstance(data["cookies"], list)
            self.assertIsInstance(data["body"], list)

    def test_no_empty_pattern_names(self) -> None:
        for key in CDN_WAF_PATTERNS:
            self.assertGreater(len(key.strip()), 0)


@pytest.mark.unit
class TestKnownProviders(unittest.TestCase):
    def test_cloudflare_present(self) -> None:
        self.assertIn("Cloudflare", CDN_WAF_PATTERNS)
        self.assertIn("cf-ray", CDN_WAF_PATTERNS["Cloudflare"]["headers"])
        self.assertIn("__cf_bm", CDN_WAF_PATTERNS["Cloudflare"]["cookies"])

    def test_aws_cloudfront_present(self) -> None:
        self.assertIn("AWS CloudFront", CDN_WAF_PATTERNS)
        self.assertIn("x-amz-cf-id", CDN_WAF_PATTERNS["AWS CloudFront"]["headers"])

    def test_aws_waf_present(self) -> None:
        self.assertIn("AWS WAF", CDN_WAF_PATTERNS)
        self.assertTrue(
            any("AWS WAF" in b for b in CDN_WAF_PATTERNS["AWS WAF"]["body"])
        )

    def test_akamai_present(self) -> None:
        self.assertIn("Akamai", CDN_WAF_PATTERNS)
        self.assertIn("abck", CDN_WAF_PATTERNS["Akamai"]["cookies"])

    def test_fastly_present(self) -> None:
        self.assertIn("Fastly", CDN_WAF_PATTERNS)

    def test_imperva_incapsula_present(self) -> None:
        self.assertIn("Imperva/Incapsula", CDN_WAF_PATTERNS)
        self.assertIn("incap_ses", CDN_WAF_PATTERNS["Imperva/Incapsula"]["cookies"])

    def test_sucuri_present(self) -> None:
        self.assertIn("Sucuri", CDN_WAF_PATTERNS)

    def test_barracuda_present(self) -> None:
        self.assertIn("Barracuda WAF", CDN_WAF_PATTERNS)

    def test_f5_big_ip_present(self) -> None:
        self.assertIn("F5 BIG-IP", CDN_WAF_PATTERNS)
        self.assertIn("MRHSession", CDN_WAF_PATTERNS["F5 BIG-IP"]["cookies"])

    def test_modsecurity_present(self) -> None:
        self.assertIn("ModSecurity", CDN_WAF_PATTERNS)
        self.assertTrue(
            any("mod_security" in b for b in CDN_WAF_PATTERNS["ModSecurity"]["body"])
        )

    def test_fortiweb_present(self) -> None:
        self.assertIn("FortiWeb WAF", CDN_WAF_PATTERNS)

    def test_azure_front_door_present(self) -> None:
        self.assertIn("Azure Front Door", CDN_WAF_PATTERNS)
        self.assertIn("x-azure-ref", CDN_WAF_PATTERNS["Azure Front Door"]["headers"])

    def test_google_cloud_cdn_present(self) -> None:
        self.assertIn("Google Cloud CDN", CDN_WAF_PATTERNS)

    def test_nginx_naxsi_present(self) -> None:
        self.assertIn("nginx WAF (NAXSI)", CDN_WAF_PATTERNS)
        self.assertIn("blocked by naxsi", CDN_WAF_PATTERNS["nginx WAF (NAXSI)"]["body"])

    def test_radware_appwall_present(self) -> None:
        self.assertIn("Radware AppWall", CDN_WAF_PATTERNS)

    def test_stackpath_present(self) -> None:
        self.assertIn("StackPath", CDN_WAF_PATTERNS)

    def test_zscaler_present(self) -> None:
        self.assertIn("Zscaler/ZScaler", CDN_WAF_PATTERNS)


@pytest.mark.unit
class TestPatternQuality(unittest.TestCase):
    def test_no_duplicate_provider_names(self) -> None:
        self.assertEqual(len(CDN_WAF_PATTERNS), len(set(CDN_WAF_PATTERNS.keys())))

    def test_patterns_cover_well_known_set(self) -> None:
        expected = {
            "Cloudflare",
            "AWS CloudFront",
            "AWS WAF",
            "Akamai",
            "Fastly",
            "Imperva/Incapsula",
            "Sucuri",
            "Barracuda WAF",
        }
        self.assertTrue(expected.issubset(CDN_WAF_PATTERNS.keys()))

    def test_header_strings_are_lowercase_or_specific(self) -> None:
        # Some patterns intentionally use mixed case like "Incapsula" - just
        # ensure no entries are blank
        for name, data in CDN_WAF_PATTERNS.items():
            for h in data["headers"]:
                self.assertIsInstance(h, str)
                self.assertNotEqual(h.strip(), "", f"{name} has blank header")

    def test_at_least_15_providers(self) -> None:
        self.assertGreaterEqual(len(CDN_WAF_PATTERNS), 15)


if __name__ == "__main__":
    unittest.main()

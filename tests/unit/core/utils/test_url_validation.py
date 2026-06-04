"""Unit tests for src.core.utils.url_validation."""

import unittest

import pytest

from src.core.utils.url_validation import (
    ALLOWED_SCHEMES,
    PRIVATE_NETWORKS,
    build_rebind_hostname,
    detect_dns_rebinding,
    ip_to_hex_label,
    is_rebinding_service,
    is_safe_url,
    is_safe_url_with_dns_check,
)


@pytest.mark.unit
class TestIsSafeUrl(unittest.TestCase):
    def test_rejects_file_scheme(self) -> None:
        self.assertFalse(is_safe_url("file:///etc/passwd"))

    def test_rejects_ftp_scheme(self) -> None:
        self.assertFalse(is_safe_url("ftp://example.com/file.txt"))

    def test_rejects_gopher_scheme(self) -> None:
        self.assertFalse(is_safe_url("gopher://example.com:70/"))

    def test_rejects_data_scheme(self) -> None:
        self.assertFalse(is_safe_url("data:text/plain,Hello"))

    def test_rejects_javascript_scheme(self) -> None:
        self.assertFalse(is_safe_url("javascript:alert(1)"))

    def test_rejects_localhost(self) -> None:
        self.assertFalse(is_safe_url("http://localhost/"))

    def test_rejects_loopback_ipv4(self) -> None:
        self.assertFalse(is_safe_url("http://127.0.0.1/"))

    def test_rejects_loopback_ipv6(self) -> None:
        self.assertFalse(is_safe_url("http://[::1]/"))

    def test_rejects_zero_ip(self) -> None:
        self.assertFalse(is_safe_url("http://0.0.0.0/"))

    def test_rejects_aws_metadata_ip(self) -> None:
        self.assertFalse(is_safe_url("http://169.254.169.254/latest/meta-data/"))

    def test_rejects_private_10_network(self) -> None:
        self.assertFalse(is_safe_url("http://10.0.0.1/"))

    def test_rejects_private_192_168_network(self) -> None:
        self.assertFalse(is_safe_url("http://192.168.1.1/"))

    def test_rejects_private_172_16_network(self) -> None:
        self.assertFalse(is_safe_url("http://172.16.0.1/"))

    def test_rejects_link_local(self) -> None:
        self.assertFalse(is_safe_url("http://169.254.0.1/"))

    def test_rejects_missing_hostname(self) -> None:
        self.assertFalse(is_safe_url("http://"))

    def test_rejects_multicast(self) -> None:
        self.assertFalse(is_safe_url("http://224.0.0.1/"))


@pytest.mark.unit
class TestIsSafeUrlWithDnsCheck(unittest.TestCase):
    def test_rejects_localhost(self) -> None:
        self.assertFalse(is_safe_url_with_dns_check("http://localhost/"))

    def test_rejects_private_ip(self) -> None:
        self.assertFalse(is_safe_url_with_dns_check("http://10.0.0.1/"))

    def test_rejects_metadata_ip(self) -> None:
        self.assertFalse(is_safe_url_with_dns_check("http://169.254.169.254/"))

    def test_rejects_non_http_scheme(self) -> None:
        self.assertFalse(is_safe_url_with_dns_check("file:///etc/passwd"))

    def test_rejects_missing_hostname(self) -> None:
        self.assertFalse(is_safe_url_with_dns_check("http://"))


@pytest.mark.unit
class TestIpToHexLabel(unittest.TestCase):
    def test_loopback_ip(self) -> None:
        self.assertEqual(ip_to_hex_label("127.0.0.1"), "7f000001")

    def test_zero_ip(self) -> None:
        self.assertEqual(ip_to_hex_label("0.0.0.0"), "00000000")

    def test_max_ip(self) -> None:
        self.assertEqual(ip_to_hex_label("255.255.255.255"), "ffffffff")

    def test_invalid_ip_returns_empty(self) -> None:
        self.assertEqual(ip_to_hex_label("not-an-ip"), "")

    def test_partial_ip_returns_empty(self) -> None:
        self.assertEqual(ip_to_hex_label("192.168.1"), "")

    def test_ip_with_invalid_octet(self) -> None:
        self.assertEqual(ip_to_hex_label("a.b.c.d"), "")


@pytest.mark.unit
class TestBuildRebindHostname(unittest.TestCase):
    def test_builds_default_rbndr_us_hostname(self) -> None:
        result = build_rebind_hostname("127.0.0.1", "8.8.8.8")
        self.assertEqual(result, "7f000001.08080808.rbndr.us")

    def test_uses_custom_domain(self) -> None:
        result = build_rebind_hostname("127.0.0.1", "8.8.8.8", domain="custom.tld")
        self.assertEqual(result, "7f000001.08080808.custom.tld")

    def test_returns_empty_for_invalid_first_ip(self) -> None:
        self.assertEqual(build_rebind_hostname("invalid", "8.8.8.8"), "")

    def test_returns_empty_for_invalid_second_ip(self) -> None:
        self.assertEqual(build_rebind_hostname("8.8.8.8", "invalid"), "")


@pytest.mark.unit
class TestIsRebindingService(unittest.TestCase):
    def test_detects_rbndr_us(self) -> None:
        self.assertTrue(is_rebinding_service("test.rbndr.us"))

    def test_detects_nip_io(self) -> None:
        self.assertTrue(is_rebinding_service("10-0-0-1.nip.io"))

    def test_detects_sslip_io(self) -> None:
        self.assertTrue(is_rebinding_service("example.sslip.io"))

    def test_detects_localtest_me(self) -> None:
        self.assertTrue(is_rebinding_service("any.localtest.me"))

    def test_detects_interactsh(self) -> None:
        self.assertTrue(is_rebinding_service("test.interact.sh"))

    def test_detects_burpcollaborator(self) -> None:
        self.assertTrue(is_rebinding_service("test.burpcollaborator.net"))

    def test_normal_hostname_not_flagged(self) -> None:
        self.assertFalse(is_rebinding_service("example.com"))

    def test_partial_match_not_flagged(self) -> None:
        # 'rbndr.us' must be a full suffix; 'rbndrxus' should not match
        self.assertFalse(is_rebinding_service("rbndrxus.com"))


@pytest.mark.unit
class TestConstants(unittest.TestCase):
    def test_allowed_schemes_only_http_and_https(self) -> None:
        self.assertEqual(ALLOWED_SCHEMES, frozenset({"http", "https"}))

    def test_private_networks_include_loopback(self) -> None:
        loopback_found = any(
            str(net.network_address) == "127.0.0.0" for net in PRIVATE_NETWORKS
        )
        self.assertTrue(loopback_found)

    def test_private_networks_include_link_local(self) -> None:
        link_local_found = any(
            str(net.network_address) == "169.254.0.0" for net in PRIVATE_NETWORKS
        )
        self.assertTrue(link_local_found)

    def test_private_networks_include_cgnat(self) -> None:
        cgnat_found = any(str(net.network_address) == "100.64.0.0" for net in PRIVATE_NETWORKS)
        self.assertTrue(cgnat_found)


@pytest.mark.unit
class TestDetectDnsRebinding(unittest.TestCase):
    def test_returns_expected_dict_keys(self) -> None:
        # Using rounds=1 to keep it fast - mocked DNS will return same IP
        result = detect_dns_rebinding("example.com", rounds=1)
        self.assertIn("is_rebinding", result)
        self.assertIn("unique_ips", result)
        self.assertIn("ip_history", result)
        self.assertIn("rounds_succeeded", result)
        self.assertIn("private_ips", result)
        self.assertIn("public_ips", result)
        self.assertIn("risk_level", result)

    def test_risk_level_is_valid_value(self) -> None:
        result = detect_dns_rebinding("example.com", rounds=1)
        self.assertIn(result["risk_level"], {"critical", "high", "medium", "none"})

    def test_rounds_succeeded_is_int(self) -> None:
        result = detect_dns_rebinding("example.com", rounds=1)
        self.assertIsInstance(result["rounds_succeeded"], int)


if __name__ == "__main__":
    unittest.main()

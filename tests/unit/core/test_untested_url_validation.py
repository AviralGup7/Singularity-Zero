"""Coverage for SSRF URL validation helpers (no live DNS rebinding loops)."""

from __future__ import annotations

import pytest

from src.core.utils import url_validation as uv


@pytest.mark.unit
@pytest.mark.parametrize(
    ("ip", "private"),
    [
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("192.168.1.10", True),
        ("172.16.0.1", True),
        ("169.254.169.254", True),
        ("100.64.1.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("not-an-ip", False),
        ("::1", True),
        ("0.0.0.0", True),
    ],
)
def test_is_ip_private(ip: str, private: bool) -> None:
    assert uv._is_ip_private(ip) is private


@pytest.mark.unit
@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("ftp://example.com", False),
        ("file:///etc/passwd", False),
        ("http://", False),
        ("https://127.0.0.1/", False),
        ("http://localhost/admin", False),
        ("http://0.0.0.0/", False),
        ("http://169.254.169.254/latest/meta-data", False),
        ("http://10.0.0.5/", False),
        ("https://192.168.0.2/x", False),
        ("https://8.8.8.8/lookup", True),
        ("http://1.1.1.1/", True),
    ],
)
def test_is_safe_url_literals_and_schemes(url: str, expected: bool) -> None:
    assert uv.is_safe_url(url) is expected
    assert uv.is_safe_url_with_dns_check(url, timeout=0.1) is expected


@pytest.mark.unit
@pytest.mark.parametrize(
    "host",
    [
        "x.rbndr.us",
        "7f000001.01010101.rbndr.us",
        "foo.nip.io",
        "bar.sslip.io",
        "a.localtest.me",
        "b.burpcollaborator.net",
        "c.interact.sh",
        "d.dnslog.cn",
    ],
)
def test_known_rebinding_services(host: str) -> None:
    assert uv.is_rebinding_service(host) is True


@pytest.mark.unit
def test_public_host_is_not_rebinding_service() -> None:
    assert uv.is_rebinding_service("api.example.com") is False


@pytest.mark.unit
@pytest.mark.parametrize(
    ("ip", "hex_label"),
    [
        ("127.0.0.1", "7f000001"),
        ("1.2.3.4", "01020304"),
        ("255.255.255.255", "ffffffff"),
        ("8.8.8.8", "08080808"),
        ("10.0.0.1", "0a000001"),
    ],
)
def test_ip_to_hex_label(ip: str, hex_label: str) -> None:
    assert uv.ip_to_hex_label(ip) == hex_label


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["127.0.0", "a.b.c.d", "", "1.2.3.4.5"])
def test_ip_to_hex_label_rejects_bad(bad: str) -> None:
    assert uv.ip_to_hex_label(bad) == ""


@pytest.mark.unit
def test_build_rebind_hostname() -> None:
    host = uv.build_rebind_hostname("127.0.0.1", "1.1.1.1")
    assert host == "7f000001.01010101.rbndr.us"
    assert uv.is_rebinding_service(host) is True
    assert uv.build_rebind_hostname("bad", "1.1.1.1") == ""
    custom = uv.build_rebind_hostname("8.8.8.8", "1.2.3.4", domain="example.test")
    assert custom == "08080808.01020304.example.test"


@pytest.mark.unit
def test_lru_dns_insert_evicts_oldest() -> None:
    original_max = uv._DNS_CACHE_MAX_ENTRIES
    uv._DNS_CACHE.clear()
    try:
        uv._DNS_CACHE_MAX_ENTRIES = 2
        uv._lru_dns_insert("a.com", 1.0, ("1.1.1.1",))
        uv._lru_dns_insert("b.com", 2.0, ("2.2.2.2",))
        uv._lru_dns_insert("c.com", 3.0, ("3.3.3.3",))
        assert "a.com" not in uv._DNS_CACHE
        assert "b.com" in uv._DNS_CACHE
        assert "c.com" in uv._DNS_CACHE
        uv._lru_dns_insert("b.com", 4.0, ("8.8.8.8",))
        assert uv._DNS_CACHE["b.com"][1] == ("8.8.8.8",)
    finally:
        uv._DNS_CACHE_MAX_ENTRIES = original_max
        uv._DNS_CACHE.clear()

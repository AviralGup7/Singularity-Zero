"""Tests for the centralized IP validation helpers."""

from __future__ import annotations

import pytest

from src.core.utils.ip_validation import indicator_type_for, is_ip, is_ipv4


class TestIsIPv4:
    @pytest.mark.parametrize(
        "host",
        [
            "192.168.1.1",
            "10.0.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "0.0.0.0",  # noqa: S104
            "255.255.255.255",
            # Trailing dot (FQDN-style) is stripped
            "192.168.1.1.",
        ],
    )
    def test_valid_ipv4(self, host: str) -> None:
        assert is_ipv4(host), f"{host!r} should be a valid IPv4 address"

    @pytest.mark.parametrize(
        "host",
        [
            "",  # empty
            None,  # noqa: ARG001
            "   ",  # whitespace only
            "999.999.999.999",  # octet > 255
            "256.0.0.1",
            "1.2.3",  # too few octets
            "1.2.3.4.5",  # too many octets
            "example.com",
            "2001:db8::1",  # IPv6 not IPv4
            "192.168.1.1/path",  # URL contamination
            "192.168.1.1 ",  # trailing space
            "192.168.1.1\n",  # newline
            "192.168.1.1\nmalicious",  # newline injection
            "user@192.168.1.1",  # at sign
        ],
    )
    def test_invalid_ipv4(self, host) -> None:
        assert not is_ipv4(host), f"{host!r} should NOT be a valid IPv4 address"


class TestIsIP:
    @pytest.mark.parametrize(
        "host",
        [
            "192.168.1.1",
            "::1",
            "2001:db8::1",
            "fe80::1",
        ],
    )
    def test_valid_any_ip(self, host: str) -> None:
        assert is_ip(host), f"{host!r} should be a valid IP address"

    @pytest.mark.parametrize(
        "host",
        [
            "",
            None,  # noqa: ARG001
            "999.999.999.999",
            "example.com",
            "192.168.1.1/extra",
        ],
    )
    def test_invalid_any_ip(self, host) -> None:
        assert not is_ip(host), f"{host!r} should NOT be a valid IP"


class TestIndicatorTypeFor:
    def test_ipv4(self) -> None:
        assert indicator_type_for("192.168.1.1") == "IPv4"
        assert indicator_type_for("8.8.8.8") == "IPv4"

    def test_ipv6(self) -> None:
        assert indicator_type_for("2001:db8::1") == "IPv6"
        assert indicator_type_for("::1") == "IPv6"

    def test_domain(self) -> None:
        assert indicator_type_for("example.com") == "domain"
        assert indicator_type_for("sub.example.com") == "domain"

    def test_empty(self) -> None:
        assert indicator_type_for("") == "domain"
        assert indicator_type_for(None) == "domain"  # type: ignore[arg-type]

    def test_invalid_octet(self) -> None:
        # The previous regex-based check accepted this; we must not.
        assert indicator_type_for("999.999.999.999") == "domain"

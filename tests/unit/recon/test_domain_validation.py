"""Tests for the centralized domain validation and normalization helpers."""

from __future__ import annotations

import pytest

from src.recon.domain_validation import (
    DOMAIN_PATTERN,
    is_safe_domain,
    normalize_domain,
)


class TestIsSafeDomain:
    @pytest.mark.parametrize(
        "domain",
        [
            "example.com",
            "EXAMPLE.com",
            "sub.example.com",
            "deep.sub.example.com",
            "a.b.c.d.e.f.g.h.i.example.com",
            "x.io",
            "123.example.com",
            "example-with-hyphen.com",
            "1.2.3.4.nip.io",
        ],
    )
    def test_valid_domains(self, domain: str) -> None:
        assert is_safe_domain(domain), f"{domain!r} should be a valid domain"

    @pytest.mark.parametrize(
        "domain",
        [
            "",
            None,  # type: ignore[arg-type]
            "no spaces.com",
            "example .com",
            "example.com\n",
            "example.com\nmalicious",
            "example.com\r",
            "example.com\x00",
            "example.com%00",
            "example.com%0a",
            "example.com/path",
            "example.com\\path",
            "example.com:8080",
            "user@example.com",
            "example.com?foo=bar",
            "example.com#frag",
            "-example.com",  # leading hyphen on label
            "example-.com",  # trailing hyphen on label
            "." * 300,  # too long
        ],
    )
    def test_invalid_domains(self, domain) -> None:
        assert not is_safe_domain(domain), f"{domain!r} should NOT be a valid domain"


class TestNormalizeDomain:
    def test_lowercases(self) -> None:
        assert normalize_domain("EXAMPLE.COM") == "example.com"

    def test_strips_trailing_dots(self) -> None:
        assert normalize_domain("example.com.") == "example.com"
        assert normalize_domain("example.com...") == "example.com"

    def test_strips_whitespace(self) -> None:
        assert normalize_domain("  example.com  ") == "example.com"

    def test_returns_empty_for_invalid(self) -> None:
        assert normalize_domain("") == ""
        assert normalize_domain(None) == ""  # type: ignore[arg-type]
        assert normalize_domain("example.com/path") == ""
        assert normalize_domain("user@example.com") == ""
        assert normalize_domain("999.999.999.999") == ""

    def test_idempotent(self) -> None:
        once = normalize_domain("Example.COM.")
        twice = normalize_domain(once)
        assert once == twice == "example.com"


class TestDomainPattern:
    def test_pattern_is_str(self) -> None:
        assert isinstance(DOMAIN_PATTERN, str)
        assert "^(?=" in DOMAIN_PATTERN
        assert "{1,253}" in DOMAIN_PATTERN

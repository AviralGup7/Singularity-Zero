"""Unit tests for CanonicalTargetIdentity and URL Normalization."""

from src.core.contracts.canonical_target import (
    CanonicalTargetIdentity,
    canonicalize_target,
)


def test_canonicalize_target_basic() -> None:
    raw = "http://EXAMPLE.COM:80/path/to/resource"
    canon = canonicalize_target(raw)
    assert canon.scheme == "http"
    assert canon.hostname == "example.com"
    assert canon.port == 80
    assert canon.path == "/path/to/resource"
    assert canon.canonical_url == "http://example.com/path/to/resource"
    assert canon.identity_hash


def test_canonicalize_target_posix_traversal() -> None:
    raw = "https://example.com:443/api/v1/../v2/users/./profile/"
    canon = canonicalize_target(raw)
    assert canon.scheme == "https"
    assert canon.hostname == "example.com"
    assert canon.port == 443
    assert canon.path == "/api/v2/users/profile/"
    assert canon.canonical_url == "https://example.com/api/v2/users/profile/"


def test_canonicalize_target_matrix_and_queries() -> None:
    raw = "https://example.com/api;jsessionid=123/users?z=2&a=1&m=3#section1"
    canon = canonicalize_target(raw)
    assert canon.path == "/api/users"
    assert canon.query == "a=1&m=3&z=2"
    assert "#" not in canon.canonical_url
    assert canon.canonical_url == "https://example.com/api/users?a=1&m=3&z=2"


def test_canonicalize_target_idna_punycode() -> None:
    raw = "https://München.com."
    canon = canonicalize_target(raw)
    assert canon.hostname == "xn--mnchen-3ya.com"
    assert canon.canonical_url == "https://xn--mnchen-3ya.com/"


def test_canonicalize_target_dns_snapshot() -> None:
    canon = canonicalize_target("https://127.0.0.1:8443/test", resolve_dns=True, now_unix=1700000000.0)
    assert canon.dns_snapshot is not None
    assert canon.dns_snapshot.is_private_or_loopback is True
    assert canon.dns_snapshot.primary_ip == "127.0.0.1"
    assert canon.dns_snapshot.resolved_at_unix == 1700000000.0

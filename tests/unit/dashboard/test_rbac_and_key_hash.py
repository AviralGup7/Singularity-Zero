"""Regression tests for guest rank, SHA-256 key verify, and empty compare."""

from __future__ import annotations

from src.dashboard.fastapi.security import (
    ROLE_ORDER,
    compare_key,
    has_role,
    verify_api_key,
    _sha256_api_key_digest,
)


def test_guest_cannot_satisfy_admin_or_operator() -> None:
    assert ROLE_ORDER["guest"] < ROLE_ORDER["viewer"]
    assert has_role("guest", {"admin"}) is False
    assert has_role("guest", {"operator"}) is False
    assert has_role("guest", {"viewer"}) is False
    assert has_role("admin", {"admin"}) is True
    assert has_role("operator", {"viewer"}) is True


def test_sha256_stored_hash_verifies_even_when_argon2_installed() -> None:
    raw = "cp_test_key_for_sha256_compat"
    stored = _sha256_api_key_digest(raw)
    assert stored.startswith("sha256$")
    assert verify_api_key(raw, stored) is True
    assert verify_api_key("wrong", stored) is False


def test_compare_key_rejects_empty() -> None:
    assert compare_key("", "") is False
    assert compare_key("abc", "") is False
    assert compare_key("", "abc") is False
    assert compare_key("abc", "abc") is True

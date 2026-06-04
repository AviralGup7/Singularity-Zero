"""Tests for the centralized sensitive parameter / header / body-field lists."""

from __future__ import annotations

import pytest

from src.core.security import (
    SENSITIVE_BODY_FIELDS,
    SENSITIVE_HEADER_NAMES,
    SENSITIVE_NAMES,
    SENSITIVE_QUERY_PARAMS,
    is_sensitive_name,
    reject_if_query_contains_credentials,
)


class TestIsSensitiveName:
    @pytest.mark.parametrize(
        "name",
        [
            "Authorization",
            "authorization",
            "AUTHORIZATION",
            "Cookie",
            "Set-Cookie",
            "X-API-Key",
            "x-api-key",
            "X-Secret-Key",
            "x-secret-key",
            "X-Access-Token",
            "X-Auth-Token",
            "Proxy-Authorization",
            "token",
            "Token",
            "TOKEN",
            "password",
            "PASSWORD",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
        ],
    )
    def test_known_sensitive_names_detected(self, name: str) -> None:
        assert is_sensitive_name(name), f"{name!r} should be flagged sensitive"

    @pytest.mark.parametrize(
        "name",
        [
            "username",
            "email",
            "X-Request-ID",
            "Content-Type",
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "page",
            "limit",
            "offset",
            "q",
            "",
        ],
    )
    def test_benign_names_not_flagged(self, name: str) -> None:
        assert not is_sensitive_name(name), f"{name!r} should NOT be flagged"

    def test_empty_and_none_safe(self) -> None:
        assert not is_sensitive_name("")
        assert not is_sensitive_name(None)  # type: ignore[arg-type]

    def test_case_insensitive(self) -> None:
        assert is_sensitive_name("Authorization") is is_sensitive_name("AUTHORIZATION")
        assert is_sensitive_name("X-Api-Key") is is_sensitive_name("x-api-key")


class TestFrozensets:
    def test_header_set_is_frozenset(self) -> None:
        assert isinstance(SENSITIVE_HEADER_NAMES, frozenset)
        assert "authorization" in SENSITIVE_HEADER_NAMES
        assert "x-api-key" in SENSITIVE_HEADER_NAMES

    def test_query_set_is_frozenset(self) -> None:
        assert isinstance(SENSITIVE_QUERY_PARAMS, frozenset)
        assert "token" in SENSITIVE_QUERY_PARAMS
        assert "password" in SENSITIVE_QUERY_PARAMS

    def test_body_set_is_frozenset(self) -> None:
        assert isinstance(SENSITIVE_BODY_FIELDS, frozenset)
        assert "password" in SENSITIVE_BODY_FIELDS
        assert "api_key" in SENSITIVE_BODY_FIELDS

    def test_union_includes_all_three(self) -> None:
        assert SENSITIVE_HEADER_NAMES <= SENSITIVE_NAMES
        assert SENSITIVE_QUERY_PARAMS <= SENSITIVE_NAMES
        assert SENSITIVE_BODY_FIELDS <= SENSITIVE_NAMES


class TestRejectIfQueryContainsCredentials:
    def test_empty_params(self) -> None:
        assert reject_if_query_contains_credentials({}) == []

    def test_no_credentials(self) -> None:
        assert reject_if_query_contains_credentials({"page": "1", "q": "x"}) == []

    def test_single_credential(self) -> None:
        assert reject_if_query_contains_credentials({"token": "abc"}) == ["token"]

    def test_multiple_credentials_sorted_unique(self) -> None:
        params = {"token": "abc", "password": "x", "page": "1", "Token": "y"}
        leaked = reject_if_query_contains_credentials(params)
        # Case-insensitive match — "token" and "Token" are the same
        assert "token" in leaked
        assert "password" in leaked
        assert "page" not in leaked
        # No duplicates
        assert len(leaked) == len(set(leaked))
        # Sorted case-insensitively
        assert leaked == sorted(leaked, key=str.lower)

    def test_works_with_arbitrary_mapping(self) -> None:
        class _Pseudo:
            def keys(self):
                return ["Authorization", "page"]

        # Original case is preserved in the output, but matching is case-insensitive
        result = reject_if_query_contains_credentials(_Pseudo())
        assert "Authorization" in result
        assert "page" not in result

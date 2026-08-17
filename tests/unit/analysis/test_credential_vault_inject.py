"""Regression: credential vault must not double-prefix Bearer tokens."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.analysis.active.auth.credential_vault import CredentialVault


@pytest.mark.unit
def test_inject_bearer_does_not_double_prefix() -> None:
    vault = CredentialVault()
    captured = vault.capture_from_response(
        {
            "url": "https://app.example.com/login",
            "headers": {"Authorization": "Bearer tok_abc"},
        }
    )
    assert captured
    assert captured[0].type == "bearer"
    request: dict[str, object] = {"headers": {}}
    vault.inject_into_request(request, "https://app.example.com/api/me")
    assert request["headers"]["Authorization"] == "Bearer tok_abc"


@pytest.mark.unit
def test_inject_cookie_appends_without_clobbering() -> None:
    vault = CredentialVault()
    vault.capture_from_response(
        {
            "url": "https://app.example.com/login",
            "headers": {"Set-Cookie": "sid=abc123"},
        }
    )
    request = {"headers": {"Cookie": "theme=dark"}}
    vault.inject_into_request(request, "https://app.example.com/dashboard")
    cookie = request["headers"]["Cookie"]
    assert "theme=dark" in cookie
    assert "sid=abc123" in cookie


@pytest.mark.unit
def test_expired_credential_is_not_injected() -> None:
    vault = CredentialVault()
    captured = vault.capture_from_response(
        {
            "url": "https://app.example.com/login",
            "headers": {"Authorization": "Bearer tok_abc"},
        }
    )
    captured[0].expires_at = datetime.now(UTC) - timedelta(minutes=1)
    vault._credentials[captured[0].credential_id] = captured[0]
    request: dict[str, object] = {"headers": {}}
    vault.inject_into_request(request, "https://app.example.com/api")
    assert "Authorization" not in request["headers"]


@pytest.mark.unit
def test_wrong_host_is_not_injected() -> None:
    vault = CredentialVault()
    vault.capture_from_response(
        {
            "url": "https://app.example.com/login",
            "headers": {"Authorization": "Bearer tok_abc"},
        }
    )
    request: dict[str, object] = {"headers": {}}
    vault.inject_into_request(request, "https://other.example.net/api")
    assert request["headers"] == {}


@pytest.mark.unit
def test_add_scan_host_and_basic_auth_passthrough() -> None:
    vault = CredentialVault()
    vault.add_scan_host("https://App.Example.com:8443/x")
    assert "app.example.com" in vault.scan_host_netlocs
    captured = vault.capture_from_response(
        {
            "url": "https://app.example.com/login",
            "headers": {"Authorization": "Basic dXNlcjpwYXNz"},
        }
    )
    assert captured[0].type == "authorization"
    request: dict[str, object] = {"headers": {}}
    vault.inject_into_request(request, "https://app.example.com/api")
    assert request["headers"]["Authorization"] == "Basic dXNlcjpwYXNz"

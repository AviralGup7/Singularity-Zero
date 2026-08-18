"""Coverage for previously untested OAuth misconfiguration helpers."""

from __future__ import annotations

import pytest

from src.analysis.passive.detector_oauth.detector_oauth_helpers import (
    check_response_oauth_issues,
    check_url_oauth_issues,
    is_oauth_url,
    parse_oauth_params,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "url",
    [
        "https://idp.example.com/oauth/authorize",
        "https://idp.example.com/oauth2/token",
        "https://idp.example.com/.well-known/openid-configuration",
        "https://app.example.com/callback?client_id=abc&redirect_uri=https://x",
        "https://app.example.com/cb?access_token=aaaa",
    ],
)
def test_is_oauth_url_true(url: str) -> None:
    assert is_oauth_url(url) is True


@pytest.mark.unit
@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/about",
        "https://example.com/static/app.js",
        "https://example.com/search?q=oauth",
    ],
)
def test_is_oauth_url_false(url: str) -> None:
    assert is_oauth_url(url) is False


@pytest.mark.unit
def test_parse_oauth_params_lowercases_keys_and_keeps_first_value() -> None:
    params = parse_oauth_params(
        "https://idp.example.com/oauth/authorize?Client_Id=abc&state=s1&state=s2"
    )
    assert params["client_id"] == "abc"
    assert params["state"] == "s1"


@pytest.mark.unit
def test_check_url_oauth_issues_ignores_non_oauth() -> None:
    assert check_url_oauth_issues("https://example.com/about") == []


@pytest.mark.unit
def test_check_url_oauth_issues_flags_missing_state_and_pkce() -> None:
    url = (
        "https://idp.example.com/oauth/authorize"
        "?response_type=code&client_id=abcdefghij&redirect_uri=http://evil"
        "&scope=openid"
    )
    findings = check_url_oauth_issues(url)
    assert findings
    issues = set(findings[0]["issues"])
    assert "missing_state_parameter" in issues
    assert "missing_pkce" in issues
    assert "insecure_redirect_uri" in issues
    assert "missing_nonce_oidc" in issues
    assert findings[0]["category"] == "oauth_misconfiguration"
    assert findings[0]["severity"] in {"low", "medium", "high"}


@pytest.mark.unit
def test_check_url_oauth_issues_flags_implicit_grant_and_tokens_in_url() -> None:
    url = (
        "https://idp.example.com/oauth/authorize"
        "?response_type=token&access_token=supersecrettoken&refresh_token=rrrrrrrr"
    )
    issues = set(check_url_oauth_issues(url)[0]["issues"])
    assert "implicit_grant_flow" in issues
    assert "access_token_in_url" in issues
    assert "refresh_token_in_url" in issues


@pytest.mark.unit
def test_check_url_oauth_issues_flags_overly_permissive_scopes() -> None:
    url = (
        "https://idp.example.com/oauth/authorize"
        "?response_type=code&state=abc&code_challenge=xyz"
        "&scope=admin write delete manage"
    )
    issues = set(check_url_oauth_issues(url)[0]["issues"])
    assert "overly_permissive_scopes" in issues


@pytest.mark.unit
def test_check_response_oauth_issues_detects_tokens_and_missing_expiry() -> None:
    findings = check_response_oauth_issues(
        {
            "url": "https://idp.example.com/oauth/token",
            "body_text": (
                '{"access_token": "abcdefghijklmnop",'
                ' "refresh_token": "rstuvwxyzabcdefg"}'
            ),
            "headers": {},
        }
    )
    issue_sets = {tuple(item["issues"]) for item in findings}
    flat = {issue for item in findings for issue in item["issues"]}
    assert "access_token_in_response" in flat
    assert "refresh_token_in_response" in flat
    assert "missing_token_expiry" in flat
    assert issue_sets


@pytest.mark.unit
def test_check_response_oauth_issues_flags_implicit_grant_and_no_auth_method() -> None:
    findings = check_response_oauth_issues(
        {
            "url": "https://idp.example.com/.well-known/openid-configuration",
            "body_text": (
                '{"token_endpoint_auth_method": "none",'
                ' "grant_types_supported": ["authorization_code", "implicit"],'
                ' "scope": "admin write delete"}'
            ),
            "headers": {},
        }
    )
    flat = {issue for item in findings for issue in item["issues"]}
    assert "token_endpoint_no_auth_method" in flat
    assert "implicit_grant_supported" in flat
    assert "overly_permissive_scopes_response" in flat


@pytest.mark.unit
def test_check_response_oauth_issues_flags_redirect_without_state() -> None:
    findings = check_response_oauth_issues(
        {
            "url": "https://idp.example.com/oauth/authorize",
            "body_text": "",
            "headers": {"Location": "http://app.example.com/cb?code=abc123"},
        }
    )
    flat = {issue for item in findings for issue in item["issues"]}
    assert "missing_state_in_redirect" in flat
    assert "insecure_redirect_location" in flat


@pytest.mark.unit
def test_check_response_oauth_issues_skips_empty_url() -> None:
    assert check_response_oauth_issues({"url": "", "body_text": "{}", "headers": {}}) == []

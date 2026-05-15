"""OAuth misconfiguration detector for OWASP API2: Broken Authentication.

Passively analyzes URLs and HTTP responses for OAuth/OIDC misconfigurations
including implicit flow, missing PKCE, token exposure, missing state parameter,
open redirect patterns, scope over-permissioning, and client ID exposure.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_auth_flow_endpoint,
    is_noise_url,
    normalized_confidence,
)

_OAUTH_PATH_RE = re.compile(
    r"(?:/oauth|/authorize|/token|/callback|/openid|/oidc|/consent|/auth(?:orize)?|/sso)",
    re.IGNORECASE,
)

_IMPLICIT_FLOW_RE = re.compile(r"(?:^|&)response_type=token(?:&|$)", re.IGNORECASE)

_PKCE_MISSING_RE = re.compile(r"(?:^|&)code_challenge=", re.IGNORECASE)

_TOKEN_IN_URL_RE = re.compile(
    r"(?:^|&)(?:access_token|id_token|refresh_token|bearer|token)=[^&]+",
    re.IGNORECASE,
)

_STATE_MISSING_RE = re.compile(r"(?:^|&)response_type=", re.IGNORECASE)
_STATE_PRESENT_RE = re.compile(r"(?:^|&)state=[^&]+", re.IGNORECASE)

_OPEN_REDIRECT_CALLBACK_RE = re.compile(
    r"(?:^|&)(?:redirect_uri|callback|redirect_url|return_to|return|next|continue)=",
    re.IGNORECASE,
)

_WIDE_REDIRECT_RE = re.compile(
    r"(?:redirect_uri|callback|redirect_url|return_to|return|next|continue)=https?://[^&]*",
    re.IGNORECASE,
)

_SCOPE_OVER_PERMISSIVE_RE = re.compile(
    r"(?:^|&)scope=([^&]*)",
    re.IGNORECASE,
)

_CLIENT_ID_RE = re.compile(
    r"(?:^|&)client_id=([^&]+)",
    re.IGNORECASE,
)

_OAUTH_ERROR_RE = re.compile(
    r"(?:oauth.*error|invalid_grant|invalid_client|unauthorized_client|"
    r"invalid_redirect_uri|invalid_scope|unsupported_response_type|"
    r"access_denied|invalid_request|unsupported_grant_type)",
    re.IGNORECASE,
)

_TOKEN_IN_REDIRECT_RE = re.compile(
    r"(?:location|redirect|url).*[#?](?:access_token|id_token|token)=",
    re.IGNORECASE,
)

_DANGEROUS_SCOPES = {
    "openid",
    "profile",
    "email",
    "phone",
    "address",
    "offline_access",
    "full_access",
    "admin",
    "write",
    "delete",
    "manage",
    "superuser",
    "root",
}


def _check_implicit_flow(url: str) -> list[str]:
    """Check for OAuth implicit flow usage (response_type=token)."""
    signals = []
    if _IMPLICIT_FLOW_RE.search(urlparse(url).query):
        signals.append("implicit_flow_detected")
    return signals


def _check_pkce(url: str) -> list[str]:
    """Check for missing PKCE indicators in OAuth URLs."""
    signals = []
    query = urlparse(url).query
    has_code = bool(re.search(r"(?:^|&)response_type=code(?:&|$)", query, re.IGNORECASE))
    has_pkce = bool(_PKCE_MISSING_RE.search(query))
    if has_code and not has_pkce:
        signals.append("missing_pkce_code_challenge")
    return signals


def _check_token_in_url(url: str) -> list[str]:
    """Check for token exposure in URL parameters."""
    signals = []
    if _TOKEN_IN_URL_RE.search(urlparse(url).query):
        signals.append("token_in_url_parameter")
    return signals


def _check_state_parameter(url: str) -> list[str]:
    """Check for missing state parameter in OAuth URLs."""
    signals = []
    query = urlparse(url).query
    if _STATE_MISSING_RE.search(query) and not _STATE_PRESENT_RE.search(query):
        signals.append("missing_state_parameter")
    return signals


def _check_open_redirect_callback(url: str) -> list[str]:
    """Check for wide/open redirect patterns in OAuth callback URLs."""
    signals = []
    query = urlparse(url).query
    if _OPEN_REDIRECT_CALLBACK_RE.search(query):
        signals.append("oauth_redirect_parameter_present")
    if _WIDE_REDIRECT_RE.search(query):
        signals.append("external_redirect_in_oauth_callback")
    return signals


def _check_scope_over_permissioning(url: str) -> list[str]:
    """Check for OAuth scope over-permissioning hints."""
    signals = []
    query = urlparse(url).query
    match = _SCOPE_OVER_PERMISSIVE_RE.search(query)
    if match:
        scopes = match.group(1).split()
        dangerous_found = {s.lower() for s in scopes} & _DANGEROUS_SCOPES
        if len(scopes) > 5:
            signals.append("excessive_oauth_scopes")
        if dangerous_found:
            signals.append(f"dangerous_scopes:{','.join(sorted(dangerous_found))}")
    return signals


def _check_client_id_exposure(url: str) -> list[str]:
    """Check for client ID exposure in URLs."""
    signals = []
    query = urlparse(url).query
    match = _CLIENT_ID_RE.search(query)
    if match:
        client_id = match.group(1)
        if client_id and not client_id.startswith("$"):
            signals.append("client_id_exposed_in_url")
    return signals


def _check_oauth_errors(response: dict[str, Any]) -> list[str]:
    """Check responses for OAuth-related error messages."""
    signals = []
    body = str(response.get("body_text") or "")
    if _OAUTH_ERROR_RE.search(body):
        signals.append("oauth_error_in_response")
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    location = headers.get("location", "")
    if _OAUTH_ERROR_RE.search(location):
        signals.append("oauth_error_in_redirect")
    return signals


def _check_token_in_redirect(response: dict[str, Any]) -> list[str]:
    """Check for token exposure in redirect URLs."""
    signals = []
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    location = headers.get("location", "")
    if _TOKEN_IN_REDIRECT_RE.search(location):
        signals.append("token_in_redirect_url")
    body = str(response.get("body_text") or "")
    if _TOKEN_IN_REDIRECT_RE.search(body):
        signals.append("token_in_redirect_body")
    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "implicit_flow_detected",
        "token_in_url_parameter",
        "token_in_redirect_url",
        "token_in_redirect_body",
    }
    high_indicators = {
        "missing_pkce_code_challenge",
        "missing_state_parameter",
        "external_redirect_in_oauth_callback",
        "oauth_error_in_response",
    }
    medium_indicators = {
        "client_id_exposed_in_url",
        "excessive_oauth_scopes",
        "dangerous_scopes:",
        "oauth_redirect_parameter_present",
        "oauth_error_in_redirect",
    }
    for signal in signals:
        if signal in critical_indicators:
            return "critical"
    for signal in signals:
        if signal in high_indicators or any(signal.startswith(ind) for ind in high_indicators):
            return "high"
    for signal in signals:
        if signal in medium_indicators or any(signal.startswith(ind) for ind in medium_indicators):
            return "medium"
    return "low"


def _calculate_risk_score(signals: list[str]) -> int:
    score = 0
    severity_scores: dict[str, int] = {
        "implicit_flow_detected": 9,
        "token_in_url_parameter": 10,
        "token_in_redirect_url": 9,
        "token_in_redirect_body": 8,
        "missing_pkce_code_challenge": 7,
        "missing_state_parameter": 6,
        "external_redirect_in_oauth_callback": 7,
        "oauth_error_in_response": 5,
        "client_id_exposed_in_url": 3,
        "excessive_oauth_scopes": 4,
        "oauth_redirect_parameter_present": 3,
        "oauth_error_in_redirect": 4,
    }
    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]
        elif signal.startswith("dangerous_scopes:"):
            score += 5
    return min(score, 20)


def oauth_misconfiguration_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect OAuth misconfigurations passively.

    Analyzes URLs and responses for:
    - OAuth endpoints with implicit flow (response_type=token)
    - Missing PKCE code_challenge in authorization code flows
    - Token exposure in URL parameters (access_token, id_token, etc.)
    - Missing state parameter in OAuth authorization URLs
    - Wide/open redirect patterns in OAuth callback URLs
    - OAuth scope over-permissioning hints
    - Client ID exposure in URLs
    - OAuth-related error messages in responses
    - Token exposure in redirect URLs

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of OAuth misconfiguration findings sorted by severity.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        path = urlparse(url).path.lower()
        if not _OAUTH_PATH_RE.search(path) and not is_auth_flow_endpoint(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        signals.extend(_check_implicit_flow(url))
        signals.extend(_check_pkce(url))
        signals.extend(_check_token_in_url(url))
        signals.extend(_check_state_parameter(url))
        signals.extend(_check_open_redirect_callback(url))
        signals.extend(_check_scope_over_permissioning(url))
        signals.extend(_check_client_id_exposure(url))

        if not signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.50,
            score=risk_score,
            signals=signals,
            cap=0.95,
        )

        title_parts: list[str] = []
        if "implicit_flow_detected" in signals:
            title_parts.append("OAuth Implicit Flow Detected")
        if "token_in_url_parameter" in signals:
            title_parts.append("Token Exposed in URL")
        if "missing_pkce_code_challenge" in signals:
            title_parts.append("Missing PKCE Code Challenge")
        if "missing_state_parameter" in signals:
            title_parts.append("Missing OAuth State Parameter")
        if "external_redirect_in_oauth_callback" in signals:
            title_parts.append("Open Redirect in OAuth Callback")
        if any(s.startswith("dangerous_scopes:") for s in signals):
            title_parts.append("Dangerous OAuth Scopes")
        if "excessive_oauth_scopes" in signals:
            title_parts.append("Excessive OAuth Scopes")
        if "client_id_exposed_in_url" in signals:
            title_parts.append("Client ID Exposed in URL")

        title = "; ".join(title_parts) if title_parts else "OAuth Misconfiguration Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        path = urlparse(url).path.lower()
        if not _OAUTH_PATH_RE.search(path) and not is_auth_flow_endpoint(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        signals.extend(_check_oauth_errors(response))
        signals.extend(_check_token_in_redirect(response))

        if not signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.50,
            score=risk_score,
            signals=signals,
            cap=0.95,
        )

        title_parts: list[str] = []
        if "oauth_error_in_response" in signals:
            title_parts.append("OAuth Error in Response")
        if "token_in_redirect_url" in signals:
            title_parts.append("Token in Redirect URL")
        if "token_in_redirect_body" in signals:
            title_parts.append("Token in Redirect Body")

        title = "; ".join(title_parts) if title_parts else "OAuth Response Issue Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]

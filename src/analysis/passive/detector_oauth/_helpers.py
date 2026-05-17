"""Helper functions for OAuth misconfiguration detection."""

import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_noise_url,
    normalized_confidence,
)

from ._constants import (
    DANGEROUS_SCOPES,
    OAUTH_AUTHZ_PATHS,
    OAUTH_TOKEN_PATHS,
    OAUTH_WELL_KNOWN_PATHS,
)


def is_oauth_url(url: str) -> bool:
    """Check if a URL looks like an OAuth endpoint."""
    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    query_lower = parsed.query.lower()

    for auth_path in OAUTH_AUTHZ_PATHS:
        if path_lower.endswith(auth_path):
            return True
    for token_path in OAUTH_TOKEN_PATHS:
        if path_lower.endswith(token_path):
            return True
    for well_known in OAUTH_WELL_KNOWN_PATHS:
        if path_lower.endswith(well_known):
            return True

    oauth_indicators = [
        "client_id=",
        "redirect_uri=",
        "response_type=",
        "scope=",
        "access_token=",
        "refresh_token=",
        "code_challenge=",
        "code_verifier=",
    ]
    for indicator in oauth_indicators:
        if indicator in query_lower:
            return True

    return False


def parse_oauth_params(url: str) -> dict[str, str]:
    """Parse OAuth parameters from a URL."""
    parsed = urlparse(url)
    params: dict[str, str] = {}
    for key, values in parse_qs(parsed.query).items():
        if values:
            params[key.lower()] = values[0]
    return params


def check_url_oauth_issues(url: str) -> list[dict[str, Any]]:
    """Check a single URL for OAuth misconfigurations."""
    issues: list[str] = []
    evidence_parts: list[str] = []
    severity_score = 0

    if not is_oauth_url(url):
        return []

    parsed = urlparse(url)
    path_lower = parsed.path.lower()
    params = parse_oauth_params(url)

    is_authz = any(path_lower.endswith(p) for p in OAUTH_AUTHZ_PATHS)
    is_token = any(path_lower.endswith(p) for p in OAUTH_TOKEN_PATHS)

    if is_authz:
        response_type = params.get("response_type", "")

        if "state" not in params:
            issues.append("missing_state_parameter")
            evidence_parts.append("state parameter absent from authorization request")
            severity_score += 4

        if "nonce" not in params and "openid" in params.get("scope", "").lower():
            issues.append("missing_nonce_oidc")
            evidence_parts.append("nonce parameter absent in OIDC flow")
            severity_score += 3

        if response_type == "token":
            issues.append("implicit_grant_flow")
            evidence_parts.append("response_type=token indicates implicit grant flow")
            severity_score += 5
        elif response_type == "id_token" or response_type == "id_token token":
            issues.append("implicit_grant_flow")
            evidence_parts.append(f"response_type={response_type} indicates implicit/hybrid flow")
            severity_score += 5

        redirect_uri = params.get("redirect_uri", "")
        if redirect_uri and redirect_uri.startswith("http://"):
            issues.append("insecure_redirect_uri")
            evidence_parts.append(f"redirect_uri uses HTTP: {redirect_uri[:80]}")
            severity_score += 4

        if "code_challenge" not in params and response_type == "code":
            issues.append("missing_pkce")
            evidence_parts.append("PKCE code_challenge not present in authorization code flow")
            severity_score += 3

        client_id = params.get("client_id", "")
        if client_id and len(client_id) > 8:
            issues.append("client_id_exposed")
            evidence_parts.append(f"client_id visible in URL: {client_id[:20]}...")
            severity_score += 1

        scope = params.get("scope", "")
        if scope:
            scope_set = set(scope.lower().split())
            dangerous_found = scope_set & DANGEROUS_SCOPES
            if len(dangerous_found) >= 3:
                issues.append("overly_permissive_scopes")
                evidence_parts.append(
                    f"broad scopes requested: {', '.join(sorted(dangerous_found)[:5])}"
                )
                severity_score += 3
            elif dangerous_found:
                issues.append("sensitive_scopes")
                evidence_parts.append(f"sensitive scopes: {', '.join(sorted(dangerous_found)[:5])}")
                severity_score += 2

    if is_token:
        if "authorization" not in params and "client_id" in params:
            issues.append("token_endpoint_no_auth")
            evidence_parts.append(
                "token endpoint accessed with client_id but no authorization header"
            )
            severity_score += 3

    access_token = params.get("access_token", "")
    if access_token:
        issues.append("access_token_in_url")
        evidence_parts.append("access_token exposed in URL parameters")
        severity_score += 5

    refresh_token = params.get("refresh_token", "")
    if refresh_token:
        issues.append("refresh_token_in_url")
        evidence_parts.append("refresh_token exposed in URL parameters")
        severity_score += 5

    code_verifier = params.get("code_verifier", "")
    if code_verifier:
        issues.append("code_verifier_in_url")
        evidence_parts.append("PKCE code_verifier exposed in URL")
        severity_score += 4

    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri:
        try:
            redirect_parsed = urlparse(redirect_uri)
            if redirect_parsed.netloc and redirect_parsed.netloc != parsed.netloc:
                if redirect_parsed.scheme == "http":
                    issues.append("open_redirect_http")
                    evidence_parts.append(f"redirect to external HTTP URL: {redirect_uri[:80]}")
                    severity_score += 3
        except Exception:  # noqa: S110
            pass

    if not issues:
        return []

    if severity_score >= 8:
        severity = "high"
    elif severity_score >= 4:
        severity = "medium"
    else:
        severity = "low"

    return [
        {
            "url": url,
            "endpoint_key": endpoint_signature(url),
            "endpoint_type": classify_endpoint(url),
            "issues": sorted(issues),
            "severity": severity,
            "confidence": round(
                normalized_confidence(
                    base=0.50,
                    score=severity_score,
                    signals=issues,
                    cap=0.92,
                ),
                2,
            ),
            "category": "oauth_misconfiguration",
            "title": f"OAuth misconfiguration: {', '.join(issues[:3])}",
            "evidence": "; ".join(evidence_parts),
            "risk_score": severity_score,
        }
    ]


def check_response_oauth_issues(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Check a single HTTP response for OAuth misconfigurations."""
    url = str(response.get("url", "")).strip()
    if not url or is_noise_url(url):
        return []

    body = str(response.get("body_text") or "")
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    int(response.get("status_code") or 0)

    results: list[dict[str, Any]] = []

    if body:
        body_lower = body.lower()

        if any(p in body_lower for p in ('"access_token"', "'access_token'", "access_token:")):
            token_match = re.search(
                r'["\']?access_token["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', body
            )
            if token_match:
                token_val = token_match.group(1)
                results.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_type": classify_endpoint(url),
                        "issues": ["access_token_in_response"],
                        "severity": "high",
                        "confidence": round(
                            normalized_confidence(
                                base=0.60,
                                score=6,
                                signals=["access_token_in_response"],
                                cap=0.95,
                            ),
                            2,
                        ),
                        "category": "oauth_misconfiguration",
                        "title": "OAuth access_token exposed in response body",
                        "evidence": f"access_token found in response: {token_val[:20]}...",
                        "risk_score": 6,
                    }
                )

        if any(p in body_lower for p in ('"refresh_token"', "'refresh_token'", "refresh_token:")):
            token_match = re.search(
                r'["\']?refresh_token["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', body
            )
            if token_match:
                token_val = token_match.group(1)
                results.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_type": classify_endpoint(url),
                        "issues": ["refresh_token_in_response"],
                        "severity": "high",
                        "confidence": round(
                            normalized_confidence(
                                base=0.60,
                                score=6,
                                signals=["refresh_token_in_response"],
                                cap=0.95,
                            ),
                            2,
                        ),
                        "category": "oauth_misconfiguration",
                        "title": "OAuth refresh_token exposed in response body",
                        "evidence": f"refresh_token found in response: {token_val[:20]}...",
                        "risk_score": 6,
                    }
                )

        if "expires_in" not in body_lower and any(
            p in body_lower for p in ('"access_token"', "'access_token'")
        ):
            results.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": ["missing_token_expiry"],
                    "severity": "medium",
                    "confidence": round(
                        normalized_confidence(
                            base=0.45,
                            score=3,
                            signals=["missing_token_expiry"],
                            cap=0.80,
                        ),
                        2,
                    ),
                    "category": "oauth_misconfiguration",
                    "title": "OAuth token response missing expiry",
                    "evidence": "access_token present but no expires_in or expiry field found",
                    "risk_score": 3,
                }
            )

        try:
            parsed_body = json.loads(body)
            if isinstance(parsed_body, dict):
                scopes = parsed_body.get("scope", "")
                if isinstance(scopes, str) and scopes:
                    scope_set = set(scopes.lower().split())
                    dangerous_found = scope_set & DANGEROUS_SCOPES
                    if len(dangerous_found) >= 3:
                        results.append(
                            {
                                "url": url,
                                "endpoint_key": endpoint_signature(url),
                                "endpoint_type": classify_endpoint(url),
                                "issues": ["overly_permissive_scopes_response"],
                                "severity": "medium",
                                "confidence": round(
                                    normalized_confidence(
                                        base=0.50,
                                        score=4,
                                        signals=["overly_permissive_scopes"],
                                        cap=0.85,
                                    ),
                                    2,
                                ),
                                "category": "oauth_misconfiguration",
                                "title": "OAuth response grants overly permissive scopes",
                                "evidence": f"granted scopes: {', '.join(sorted(dangerous_found)[:5])}",
                                "risk_score": 4,
                            }
                        )

                if "token_endpoint_auth_method" in parsed_body:
                    auth_method = str(parsed_body.get("token_endpoint_auth_method", "")).lower()
                    if auth_method in ("none", ""):
                        results.append(
                            {
                                "url": url,
                                "endpoint_key": endpoint_signature(url),
                                "endpoint_type": classify_endpoint(url),
                                "issues": ["token_endpoint_no_auth_method"],
                                "severity": "medium",
                                "confidence": round(
                                    normalized_confidence(
                                        base=0.50,
                                        score=4,
                                        signals=["token_endpoint_no_auth_method"],
                                        cap=0.85,
                                    ),
                                    2,
                                ),
                                "category": "oauth_misconfiguration",
                                "title": "Token endpoint allows unauthenticated access",
                                "evidence": f"token_endpoint_auth_method: {auth_method or 'none'}",
                                "risk_score": 4,
                            }
                        )

                grant_types = parsed_body.get("grant_types_supported", [])
                if isinstance(grant_types, list):
                    if "implicit" in [str(g).lower() for g in grant_types]:
                        results.append(
                            {
                                "url": url,
                                "endpoint_key": endpoint_signature(url),
                                "endpoint_type": classify_endpoint(url),
                                "issues": ["implicit_grant_supported"],
                                "severity": "medium",
                                "confidence": round(
                                    normalized_confidence(
                                        base=0.55,
                                        score=4,
                                        signals=["implicit_grant_supported"],
                                        cap=0.85,
                                    ),
                                    2,
                                ),
                                "category": "oauth_misconfiguration",
                                "title": "OAuth server supports implicit grant flow",
                                "evidence": f"grant_types_supported includes implicit: {grant_types}",
                                "risk_score": 4,
                            }
                        )
        except json.JSONDecodeError, ValueError:
            pass

    location_header = headers.get("location", "")
    if location_header:
        loc_lower = location_header.lower()
        if any(p in loc_lower for p in ("state=", "code=", "token=", "access_token=")):
            loc_parsed = urlparse(location_header)
            loc_params = parse_oauth_params(location_header)
            if "state" not in loc_params and ("code" in loc_params or "token" in loc_params):
                results.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_type": classify_endpoint(url),
                        "issues": ["missing_state_in_redirect"],
                        "severity": "medium",
                        "confidence": round(
                            normalized_confidence(
                                base=0.50,
                                score=4,
                                signals=["missing_state_in_redirect"],
                                cap=0.85,
                            ),
                            2,
                        ),
                        "category": "oauth_misconfiguration",
                        "title": "OAuth redirect missing state parameter",
                        "evidence": f"Location header redirect without state: {location_header[:100]}",
                        "risk_score": 4,
                    }
                )

            if loc_parsed.scheme == "http" and loc_parsed.netloc:
                results.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_signature(url),
                        "endpoint_type": classify_endpoint(url),
                        "issues": ["insecure_redirect_location"],
                        "severity": "medium",
                        "confidence": round(
                            normalized_confidence(
                                base=0.50,
                                score=3,
                                signals=["insecure_redirect_location"],
                                cap=0.80,
                            ),
                            2,
                        ),
                        "category": "oauth_misconfiguration",
                        "title": "OAuth redirect to insecure HTTP URL",
                        "evidence": f"Location header redirects to HTTP: {location_header[:100]}",
                        "risk_score": 3,
                    }
                )

    return results

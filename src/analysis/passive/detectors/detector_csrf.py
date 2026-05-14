"""CSRF protection detector for identifying endpoints lacking anti-CSRF controls.

Analyzes responses for missing CSRF tokens, weak SameSite cookie attributes,
and state-changing endpoints without proper CSRF protections.
"""

from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_auth_flow_endpoint,
    is_noise_url,
    normalized_confidence,
)

# HTTP methods that should have CSRF protection
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Headers that indicate CSRF protection
CSRF_PROTECTION_HEADERS = {
    "x-csrf-token",
    "x-xsrf-token",
    "x-csrf-header",
    "csrf-token",
    "x-xsrf-header",
}

# Cookie attributes that mitigate CSRF risk
CSRF_SAFE_SAMESITE = {"strict", "lax"}


def _check_csrf_in_body(body: str) -> list[str]:
    """Check response body for CSRF token indicators.

    Args:
        body: Response body text.

    Returns:
        List of CSRF token indicators found in the body.
    """
    signals = []
    body_lower = body.lower()

    # Check for hidden CSRF token fields in forms
    if 'name="csrf' in body_lower or 'name="xsrf' in body_lower or 'name="_token"' in body_lower:
        signals.append("csrf_hidden_field")

    # Check for CSRF meta tags
    if '<meta name="csrf' in body_lower or '<meta name="xsrf' in body_lower:
        signals.append("csrf_meta_tag")

    # Check for CSRF token in JavaScript variables
    if "csrf_token" in body_lower or "xsrf_token" in body_lower:
        signals.append("csrf_js_variable")

    # Check for CSRF in data attributes
    if "data-csrf" in body_lower or "data-xsrf" in body_lower:
        signals.append("csrf_data_attribute")

    return signals


def _check_cookie_csrf_protection(headers: dict[str, Any]) -> list[str]:
    """Check Set-Cookie headers for CSRF-mitigating attributes.

    Handles multiple Set-Cookie headers properly by checking all of them.

    Args:
        headers: Response headers dict (lowercase keys).

    Returns:
        List of cookie-based CSRF protection signals.
    """
    signals = []
    # Handle both single string and list of Set-Cookie headers
    set_cookies = headers.get("set-cookie", "")
    if isinstance(set_cookies, str):
        set_cookies = [set_cookies]
    elif not isinstance(set_cookies, list):
        set_cookies = []

    for set_cookie in set_cookies:
        if not set_cookie:
            continue
        cookie_lower = set_cookie.lower()

        # Check SameSite attribute
        if "samesite=strict" in cookie_lower:
            signals.append("samesite_strict")
        elif "samesite=lax" in cookie_lower:
            signals.append("samesite_lax")

        # Check for Secure flag
        if "secure" in cookie_lower and "securepath" not in cookie_lower:
            signals.append("cookie_secure")

        # Check for HttpOnly flag
        if "httponly" in cookie_lower:
            signals.append("cookie_httponly")

    return signals


def csrf_protection_checker(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check endpoints for missing or weak CSRF protections.

    Analyzes state-changing endpoints for:
    - Missing CSRF tokens in forms/responses
    - Weak or missing SameSite cookie attributes
    - Missing CSRF protection headers
    - GET/HEAD endpoints that perform state changes (CSRF via URL)

    Args:
        urls: Set of URLs to check.
        responses: List of HTTP response dicts.

    Returns:
        List of CSRF protection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        body = str(response.get("body_text") or "")
        headers = {
            str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()
        }
        # Method may be in response metadata or we infer from URL patterns
        method = str(response.get("method", "")).upper()
        status_code = int(response.get("status_code") or 0)
        content_type = str(response.get("content_type") or "").lower()

        # Skip static content and non-HTML responses for body-based checks
        is_html = "html" in content_type or "json" in content_type or not content_type

        # Collect CSRF signals
        csrf_signals: list[str] = []
        missing_protections: list[str] = []

        # Check for CSRF tokens in response body
        if is_html and body:
            body_csrf = _check_csrf_in_body(body)
            csrf_signals.extend(body_csrf)

        # Check for CSRF protection headers
        header_csrf = CSRF_PROTECTION_HEADERS & set(headers.keys())
        if header_csrf:
            csrf_signals.append("csrf_protection_header")

        # Check cookie-based CSRF mitigation
        cookie_signals = _check_cookie_csrf_protection(headers)
        csrf_signals.extend(cookie_signals)

        # Determine if this endpoint needs CSRF protection
        # Since we can't reliably know the HTTP method from passive responses,
        # we check URL patterns and endpoint classification
        path = urlparse(url).path.lower()
        is_state_changing_path = any(
            kw in path
            for kw in (
                "/update",
                "/delete",
                "/create",
                "/modify",
                "/change",
                "/set",
                "/add",
                "/remove",
                "/edit",
                "/save",
                "/submit",
                "/process",
                "/execute",
                "/run",
                "/action",
                "/perform",
            )
        )
        needs_csrf = (
            is_state_changing_path
            or is_auth_flow_endpoint(url)
            or classify_endpoint(url) in {"AUTH", "API"}
        )

        if not needs_csrf:
            continue

        # Identify missing protections for state-changing endpoints
        has_any_csrf = bool(csrf_signals)

        if not has_any_csrf:
            missing_protections.append("no_csrf_token")

        if not any(s.startswith("samesite_") for s in csrf_signals):
            missing_protections.append("no_samesite_cookie")

        # Only report if there are missing protections
        if not missing_protections:
            continue

        # Calculate risk score
        risk_score = 0
        if "no_csrf_token" in missing_protections:
            risk_score += 5
        if "no_samesite_cookie" in missing_protections:
            risk_score += 3

        # Higher risk for auth endpoints
        if is_auth_flow_endpoint(url):
            risk_score += 2
        if is_state_changing_path:
            risk_score += 1

        # Calculate confidence based on evidence strength
        confidence = normalized_confidence(
            base=0.48,
            score=risk_score,
            signals=csrf_signals + [f"missing:{m}" for m in missing_protections],
            cap=0.90,
        )

        # Build explanation
        explanation_parts = []
        if "no_csrf_token" in missing_protections:
            explanation_parts.append("No CSRF token found in request or response")
        if "no_samesite_cookie" in missing_protections:
            explanation_parts.append("Missing SameSite cookie attribute for CSRF mitigation")
        if is_auth_flow_endpoint(url):
            explanation_parts.append("Authentication flow endpoint increases risk")
        if is_state_changing_path:
            explanation_parts.append("State-changing endpoint path without CSRF protection")

        # Calculate severity based on risk score
        if risk_score >= 7:
            severity = "high"
        elif risk_score >= 4:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "method": method,
                "status_code": status_code,
                "csrf_signals": sorted(csrf_signals),
                "missing_protections": sorted(missing_protections),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": "; ".join(explanation_parts)
                if explanation_parts
                else "CSRF protection gap detected",
                "auth_endpoint": is_auth_flow_endpoint(url),
                "signals": sorted(
                    {
                        "csrf_protection_gap",
                        "auth_endpoint" if is_auth_flow_endpoint(url) else "",
                        "state_changing_path" if is_state_changing_path else "",
                        *csrf_signals,
                    }
                    - {""}
                ),
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings

"""API endpoint security analysis.

Analyzes API endpoints for common security issues including:
- Missing authentication on sensitive endpoints
- Excessive data exposure in responses
- Missing rate limiting
- Insecure HTTP methods
- Version disclosure
- Mass assignment potential
"""

import json
import re
from typing import Any

from src.analysis.helpers import endpoint_base_key, endpoint_signature, normalize_headers
from src.core.plugins import register_plugin

# Sensitive API path patterns that should require authentication
SENSITIVE_API_PATTERNS = [
    "/admin",
    "/user",
    "/account",
    "/profile",
    "/settings",
    "/payment",
    "/billing",
    "/subscription",
    "/order",
    "/token",
    "/auth",
    "/session",
    "/login",
    "/api/internal",
    "/api/admin",
    "/api/private",
    "/graphql",
    "/graphql/console",
]

# HTTP methods that should be restricted on sensitive endpoints
RESTRICTED_METHODS = {"DELETE", "PUT", "PATCH"}

# Response fields that indicate excessive data exposure
SENSITIVE_RESPONSE_FIELDS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session_id",
    "ssn",
    "credit_card",
    "card_number",
    "cvv",
    "private_key",
    "internal_id",
    "debug",
    "stack_trace",
    "error_detail",
}


ENRICHMENT_PROVIDER = "enrichment_provider"


@register_plugin(ENRICHMENT_PROVIDER, "api_security")
def api_security_analyzer(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Analyze API endpoints for common security issues.

    Args:
        responses: List of response dicts to analyze.

    Returns:
        List of API security finding dicts.
    """
    findings: list[dict[str, Any]] = []

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue

        # Only analyze API endpoints
        if "/api/" not in url.lower() and "/graphql" not in url.lower():
            continue

        headers = normalize_headers(response)
        body_text = str(response.get("body_text", "")).lower()
        status_code = int(response.get("status_code") or 0)

        issues: list[str] = []
        severity = "low"

        # Check for missing authentication on sensitive endpoints
        is_sensitive = any(pattern in url.lower() for pattern in SENSITIVE_API_PATTERNS)
        if is_sensitive and status_code == 200:
            # Check if auth headers were required
            auth_headers = {"authorization", "x-api-key", "x-auth-token", "cookie"}
            request_headers = {h.lower() for h in (response.get("request_headers") or {})}
            if not auth_headers & request_headers:
                issues.append("missing_auth_on_sensitive_endpoint")
                severity = "high"

        # Check for excessive data exposure
        if body_text:
            try:
                body_json = json.loads(body_text)
                if isinstance(body_json, dict):
                    exposed_fields = set(body_json.keys()) & SENSITIVE_RESPONSE_FIELDS
                    if exposed_fields:
                        issues.append(
                            f"excessive_data_exposure:{','.join(sorted(exposed_fields)[:5])}"
                        )
                        severity = "high" if severity != "critical" else severity
            except json.JSONDecodeError, TypeError:
                pass

        # Check for missing rate limiting headers on API endpoints
        rate_limit_headers = {
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "ratelimit-limit",
            "ratelimit-remaining",
            "ratelimit-reset",
        }
        response_headers = {h.lower() for h in headers.keys()}
        if not rate_limit_headers & response_headers:
            issues.append("missing_rate_limit_headers")
            if severity == "low":
                severity = "medium"

        # Check for API version disclosure in URL
        version_match = re.search(r"/v(\d+)/", url)
        if version_match:
            version = version_match.group(1)
            # Old API versions may have known vulnerabilities
            if int(version) <= 1:
                issues.append(f"legacy_api_version:v{version}")
                if severity == "low":
                    severity = "medium"

        # Check for unsafe HTTP methods allowed
        allow_header = headers.get("allow", "")
        if allow_header:
            allowed_methods = {m.strip().upper() for m in allow_header.split(",")}
            unsafe_methods = allowed_methods & RESTRICTED_METHODS
            if unsafe_methods:
                issues.append(f"unsafe_methods_allowed:{','.join(sorted(unsafe_methods))}")
                if severity == "low":
                    severity = "medium"

        # Check for missing security headers on API responses
        if not headers.get("x-content-type-options", "").lower() == "nosniff":
            issues.append("missing_x_content_type_options")
        if not headers.get("cache-control", "").lower():
            # API responses should have cache control
            issues.append("missing_cache_control")

        if issues:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "status_code": status_code,
                    "issues": sorted(issues),
                    "severity": severity,
                    "confidence": 0.75 if severity in ("high", "critical") else 0.60,
                    "category": "api_security",
                    "title": f"API security issue: {issues[0]}",
                    "evidence": {
                        "url": url,
                        "status_code": status_code,
                        "issues": issues,
                    },
                }
            )

    findings.sort(
        key=lambda item: (
            0 if item["severity"] in ("critical", "high") else 1,
            -len(item["issues"]),
            item["url"],
        )
    )
    return findings[:50]

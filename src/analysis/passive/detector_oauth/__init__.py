"""OAuth misconfiguration detector for OWASP API2: Broken Authentication.

Passive analyzer for HTTP responses and URLs that detects OAuth 2.0 / OIDC
misconfigurations including missing state parameter, insecure redirect URIs,
implicit grant flow usage, missing PKCE, exposed tokens, and open redirects.

This package modularizes the OAuth detector into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any

from src.analysis.helpers import is_noise_url

from ._constants import (
    DANGEROUS_SCOPES,
    OAUTH_AUTHZ_PATHS,
    OAUTH_MISCONFIGURATION_PROBE_SPEC,
    OAUTH_TOKEN_PATHS,
    OAUTH_WELL_KNOWN_PATHS,
    OVERLY_PERMISSIVE_SCOPE_COMBOS,
)
from ._helpers import (
    check_response_oauth_issues,
    check_url_oauth_issues,
    is_oauth_url,
    parse_oauth_params,
)

__all__ = [
    "oauth_misconfiguration_detector",
    "OAUTH_MISCONFIGURATION_PROBE_SPEC",
    "is_oauth_url",
    "parse_oauth_params",
    "check_url_oauth_issues",
    "check_response_oauth_issues",
    "DANGEROUS_SCOPES",
    "OAUTH_AUTHZ_PATHS",
    "OAUTH_TOKEN_PATHS",
    "OAUTH_WELL_KNOWN_PATHS",
    "OVERLY_PERMISSIVE_SCOPE_COMBOS",
]


def oauth_misconfiguration_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect OAuth/OIDC misconfigurations from URLs and responses."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue
        url_findings = check_url_oauth_issues(url)
        for finding in url_findings:
            endpoint_key = finding.get("endpoint_key", "")
            if endpoint_key not in seen:
                seen.add(endpoint_key)
                findings.append(finding)

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue
        endpoint_key = f"resp:{url}"
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        response_findings = check_response_oauth_issues(response)
        findings.extend(response_findings)

    findings.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(item.get("severity", "low"), 3),
            -item.get("risk_score", 0),
            item.get("url", ""),
        )
    )
    return findings[:limit]

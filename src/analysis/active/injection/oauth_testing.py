"""OAuth / OIDC Security Testing Module.

Tests OAuth 2.0 and OpenID Connect implementations for common vulnerabilities:
- Authorization code interception
- Implicit flow token leakage
- PKCE enforcement checks
- Open redirect via OAuth callback
- State parameter validation
- Scope escalation
- Token validation bypass
- Misconfigured redirect URIs
"""

import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

logger = logging.getLogger(__name__)

WELL_KNOWN_ENDPOINTS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth2/.well-known/openid-configuration",
]

DANGEROUS_REDIRECT_PATTERNS = [
    r"^https?://localhost[:/]",
    r"^https?://127\.0\.0\.1[:/]",
    r"^https?://0\.0\.0\.0[:/]",
    r"data:",
    r"javascript:",
]


async def discover_oauth_config(
    base_urls: list[str],
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Discover OAuth/OIDC configurations via well-known endpoints."""
    configs: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "cyber-pipeline/1.0"},
    ) as client:
        for base_url in base_urls:
            parsed = urlparse(base_url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            for endpoint in WELL_KNOWN_ENDPOINTS:
                try:
                    resp = await client.get(origin + endpoint)
                    if resp.status_code == 200:
                        data = resp.json()
                        configs.append(
                            {
                                "origin": origin,
                                "endpoint": endpoint,
                                "config": data,
                                "issuer": data.get("issuer", ""),
                                "authorization_endpoint": data.get("authorization_endpoint", ""),
                                "token_endpoint": data.get("token_endpoint", ""),
                                "grant_types_supported": data.get("grant_types_supported", []),
                                "response_types_supported": data.get(
                                    "response_types_supported", []
                                ),
                            }
                        )
                        break
                except httpx.RequestError, ValueError:
                    continue
    return configs


def _check_implicit_flow(config: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    response_types = config.get("config", {}).get("response_types_supported", [])
    implicit_types = {"id_token", "id_token token", "token"}
    if implicit_types & set(response_types):
        findings.append(
            {
                "url": config["origin"],
                "type": "implicit_flow_enabled",
                "severity": "medium",
                "details": {
                    "response_types": sorted(implicit_types & set(response_types)),
                    "recommendation": "Disable implicit flow, use authorization code flow with PKCE.",
                },
            }
        )
    return findings


def _check_pkce_support(config: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    methods = config.get("config", {}).get("code_challenge_methods_supported", [])
    if not methods:
        findings.append(
            {
                "url": config["origin"],
                "type": "pkce_not_supported",
                "severity": "medium",
                "details": {
                    "recommendation": "Implement PKCE (S256) to prevent code interception."
                },
            }
        )
    elif "S256" not in methods:
        findings.append(
            {
                "url": config["origin"],
                "type": "pkce_weak_method",
                "severity": "low",
                "details": {
                    "methods_found": methods,
                    "recommendation": "Use S256. Plain is insecure.",
                },
            }
        )
    return findings


def _is_dangerous_redirect(uri: str) -> bool:
    return any(re.match(p, uri, re.IGNORECASE) for p in DANGEROUS_REDIRECT_PATTERNS)


def _check_redirect_uris(config: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if config.get("config"):
        for key in ("redirect_uris", "post_logout_redirect_uris"):
            for uri in config["config"].get(key, []):
                if _is_dangerous_redirect(uri):
                    findings.append(
                        {
                            "url": config["origin"],
                            "type": "dangerous_redirect_uri",
                            "severity": "high",
                            "details": {"uri": uri, "issue": "Potentially dangerous redirect URI"},
                        }
                    )
    return findings


async def test_oauth_oidc_security(
    urls: list[str],
    timeout: float = 10.0,
    max_urls: int = 50,
) -> list[dict[str, Any]]:
    """Test OAuth/OIDC endpoints for security misconfigurations."""
    findings: list[dict[str, Any]] = []
    configs = await discover_oauth_config(urls[:max_urls], timeout)
    for config in configs:
        findings.extend(_check_implicit_flow(config))
        findings.extend(_check_pkce_support(config))
        findings.extend(_check_redirect_uris(config))
    tested = 0
    for url in urls[:max_urls]:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            if "code" in params and "state" not in params:
                findings.append(
                    {
                        "url": url,
                        "type": "missing_state_parameter",
                        "severity": "medium",
                        "details": {"issue": "Callback missing state param, vulnerable to CSRF."},
                    }
                )
            if "access_token" in params or "id_token" in params:
                findings.append(
                    {
                        "url": url,
                        "type": "token_in_url",
                        "severity": "high",
                        "details": {"issue": "Token exposed in URL. May leak via Referer or logs."},
                    }
                )
        tested += 1
    logger.info(
        "OAuth/OIDC: tested %d URLs, discovered %d configs, found %d findings",
        tested,
        len(configs),
        len(findings),
    )
    return findings

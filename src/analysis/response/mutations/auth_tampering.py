"""Authentication header tampering probes."""

from typing import Any

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache

from .diff import _variant_diff_summary


def _auth_header_variants() -> list[dict[str, Any]]:
    return [
        {"name": "stripped_auth", "description": "Remove all auth headers", "headers": {}},
        {
            "name": "invalid_bearer",
            "description": "Send invalid Bearer token",
            "headers": {"Authorization": "Bearer invalid_token_here"},
        },
        {
            "name": "malformed_jwt",
            "description": "Send malformed JWT",
            "headers": {"Authorization": "Bearer malformed.jwt.token"},
        },
        {
            "name": "basic_auth",
            "description": "Switch to Basic auth",
            "headers": {"Authorization": "Basic dXNlcjpwYXNz"},
        },
        {
            "name": "empty_auth",
            "description": "Send empty Authorization header",
            "headers": {"Authorization": ""},
        },
        {
            "name": "case_variation",
            "description": "Case variation of Bearer",
            "headers": {"Authorization": "bearer test_token"},
        },
        {
            "name": "api_key_header",
            "description": "Try X-API-Key header",
            "headers": {"X-API-Key": "test_key"},
        },
        {
            "name": "api_key_lowercase",
            "description": "Try lowercase x-api-key",
            "headers": {"x-api-key": "test_key"},
        },
    ]


def auth_header_tampering_variations(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 16
) -> list[dict[str, Any]]:
    """Test authentication header tampering variations."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url) or classify_endpoint(url) == "STATIC":
            continue
        baseline = response_cache.get(url)
        if not baseline:
            continue
        url_endpoint_key = endpoint_signature(url)
        url_endpoint_base_key = endpoint_base_key(url)
        observations = []
        for variation in _auth_header_variants():
            mutated = response_cache.request(
                url, headers={**variation["headers"], "Cache-Control": "no-cache"}
            )
            if not mutated:
                continue
            diff = _variant_diff_summary(baseline, mutated)
            auth_bypass_variant = (
                variation["name"] == "stripped_auth"
                and int(mutated.get("status_code") or 0) < 400
                and diff["body_similarity"] >= 0.9
            )
            if not (diff["changed"] or auth_bypass_variant):
                continue
            observations.append(
                {
                    "variation": variation["name"],
                    "description": variation["description"],
                    "headers": sorted(variation["headers"].keys()),
                    "auth_bypass_variant": auth_bypass_variant,
                    **diff,
                }
            )
        if observations:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": url_endpoint_key,
                    "endpoint_base_key": url_endpoint_base_key,
                    "observations": observations[:4],
                    "auth_bypass_variant": any(
                        item["auth_bypass_variant"] for item in observations
                    ),
                    "signals": sorted(
                        {
                            "auth_header_variation",
                            "status_divergence"
                            if any(item["status_changed"] for item in observations)
                            else "",
                            "content_divergence"
                            if any(item["content_changed"] for item in observations)
                            else "",
                            "possible_auth_bypass"
                            if any(item["auth_bypass_variant"] for item in observations)
                            else "",
                        }
                        - {""}
                    ),
                }
            )
    findings.sort(
        key=lambda item: (not item["auth_bypass_variant"], -len(item["observations"]), item["url"])
    )
    return findings[:limit]

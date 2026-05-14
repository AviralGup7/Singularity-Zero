"""Auth header tampering variations."""

from typing import Any

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache

from ._diff_utils import variant_diff_summary


def _auth_header_variants() -> list[dict[str, Any]]:
    return [
        {
            "name": "stripped_auth",
            "description": "Removed Authorization and Cookie headers",
            "headers": {"Authorization": "stripped", "Cookie": "stripped"},
        },
        {
            "name": "invalid_bearer",
            "description": "Invalid bearer token",
            "headers": {"Authorization": "Bearer invalid-test-token"},
        },
        {
            "name": "basic_probe",
            "description": "Basic auth probe header",
            "headers": {"Authorization": "Basic ZHVtbXk6dGVzdA=="},
        },
    ]


def auth_header_tampering_variations(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 16
) -> list[dict[str, Any]]:
    """Test endpoints with manipulated auth headers."""
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        if classify_endpoint(url) == "STATIC":
            continue
        baseline = response_cache.get(url)
        if not baseline:
            continue
        observations = []
        for variation in _auth_header_variants():
            mutated = response_cache.request(
                url,
                headers={**variation["headers"], "Cache-Control": "no-cache"},
            )
            if not mutated:
                continue
            diff = variant_diff_summary(baseline, mutated)
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
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
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

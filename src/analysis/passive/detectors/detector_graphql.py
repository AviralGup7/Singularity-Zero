"""Passive GraphQL endpoint and introspection detector."""

from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import endpoint_base_key, endpoint_signature

GRAPHQL_PATHS = {
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphiql",
    "/__graphql",
    "/console/graphql",
    "/gql",
}


def graphql_introspection_detector(
    urls: set[str], responses: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Passively detect GraphQL endpoints and potential introspection exposure. (Fix Audit #38)"""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    # 1. URL-based detection
    for url in sorted(urls):
        parsed = urlparse(url)
        path = parsed.path.lower()
        if any(gpath in path for gpath in GRAPHQL_PATHS):
            endpoint_key = endpoint_signature(url)
            if endpoint_key in seen:
                continue
            seen.add(endpoint_key)

            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": "API",
                    "category": "graphql_discovery",
                    "title": f"GraphQL endpoint discovered at {url}",
                    "severity": "info",
                    "confidence": 0.90,
                    "signals": ["graphql_path_match"],
                    "explanation": f"Passive scan identified a potential GraphQL endpoint based on URL pattern: {path}",
                }
            )

    # 2. Response-based detection (Introspection exposure)
    for response in responses:
        body = str(response.get("body_text", "")).lower()
        # Look for common GraphQL introspection signatures in response bodies
        if "__schema" in body and "__typename" in body and ("query" in body or "types" in body):
            url = response.get("url", "")
            endpoint_key = endpoint_signature(url)

            # Upgrade existing discovery finding or add new one
            existing = next((f for f in findings if f["endpoint_key"] == endpoint_key), None)
            if existing:
                existing["title"] = f"GraphQL introspection exposed at {url}"
                existing["severity"] = "high"
                existing["confidence"] = 0.98
                existing["signals"].append("introspection_data_found")
                existing["explanation"] += " Introspection data was found in the response body!"
            else:
                findings.append(
                    {
                        "url": url,
                        "endpoint_key": endpoint_key,
                        "endpoint_base_key": endpoint_base_key(url),
                        "endpoint_type": "API",
                        "category": "graphql_exposure",
                        "title": f"GraphQL introspection exposed at {url}",
                        "severity": "high",
                        "confidence": 0.98,
                        "signals": ["introspection_data_found"],
                        "explanation": "Passive scan detected GraphQL introspection results in the response body.",
                        "status_code": response.get("status_code"),
                    }
                )

    return findings

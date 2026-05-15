"""Payload generator for parameter fuzzing and mutation testing.

Provides functions for generating context-aware test payloads based on
parameter type detection, delegating to the core mutation engine.
Supports query parameters, POST body fields, and HTTP header injection.
"""

from typing import Any

from src.analysis.helpers import endpoint_signature, is_noise_url, meaningful_query_pairs
from src.core.mutation_engine import generate_payloads_for_parameter


def generate_parameter_payloads(
    name: str,
    value: str,
    *,
    collaborator_domain: str = "collaborator.example",
    max_payloads_per_param: int = 10,
) -> list[dict[str, str]]:
    """Generate mutation payloads for a single parameter.

    Delegates to the core mutation engine for type-aware payload generation.

    Args:
        name: Parameter name.
        value: Current parameter value.
        collaborator_domain: Domain for out-of-band testing.
        max_payloads_per_param: Maximum payloads to generate.

    Returns:
        List of payload dicts with 'parameter', 'variant', and 'reason' keys.
    """
    return generate_payloads_for_parameter(
        name,
        value,
        collaborator_domain=collaborator_domain,
        max_payloads=max_payloads_per_param,
    )


def generate_payload_suggestions(
    priority_urls: list[str],
    *,
    limit: int = 18,
    collaborator_domain: str = "collaborator.example",
    max_payloads_per_param: int = 10,
    max_payloads_per_endpoint: int = 40,
) -> list[dict[str, Any]]:
    """Generate payload suggestions across multiple priority URLs.

    Args:
        priority_urls: List of URLs to generate payloads for.
        limit: Maximum number of URL suggestions to return.
        collaborator_domain: Domain for out-of-band testing.
        max_payloads_per_param: Max payloads per parameter.
        max_payloads_per_endpoint: Max payloads per endpoint.

    Returns:
        List of dicts with 'url', 'endpoint_key', and 'suggestions'.
    """
    suggestions: list[dict[str, Any]] = []
    seen_endpoint_keys: set[str] = set()

    for url in priority_urls:
        if len(suggestions) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen_endpoint_keys:
            continue
        seen_endpoint_keys.add(endpoint_key)

        generated: list[dict[str, str]] = []
        seen_pair: set[tuple[str, str]] = set()

        for name, value in meaningful_query_pairs(url):
            payloads = generate_parameter_payloads(
                name,
                value,
                collaborator_domain=collaborator_domain,
                max_payloads_per_param=max_payloads_per_param,
            )
            for item in payloads:
                key = (str(item.get("parameter", "")), str(item.get("variant", "")))
                if key in seen_pair:
                    continue
                seen_pair.add(key)
                generated.append(item)
                if len(generated) >= max_payloads_per_endpoint:
                    break
            if len(generated) >= max_payloads_per_endpoint:
                break

        if generated:
            suggestions.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "suggestions": generated,
                }
            )

    return suggestions

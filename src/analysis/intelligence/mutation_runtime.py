"""Mutation runtime for generating contextual URL mutations and payload suggestions.

Builds context-aware URL mutations by analyzing query parameters and generating
targeted payloads using the fuzzing engine.
"""

from typing import Any
from urllib.parse import ParseResult, parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    decode_candidate_value,
    endpoint_signature,
    is_noise_url,
    meaningful_query_pairs,
)
from src.fuzzing.payload_generator import generate_parameter_payloads
from src.recon.common import normalize_url


def build_contextual_diff_mutation(url: str) -> dict[str, Any] | None:
    """Build a single contextual mutation for a URL's first meaningful parameter.

    Args:
        url: URL to mutate.

    Returns:
        Dict with mutated URL, parameter details, and mutation reason, or None.
    """
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for index, (key, value) in enumerate(query_pairs):
        name = key.strip().lower()
        decoded = decode_candidate_value(value)
        if not name:
            continue
        payloads = generate_parameter_payloads(name, decoded, max_payloads_per_param=10)
        if payloads:
            selected = payloads[0]
            return apply_query_pair_replacement(
                parsed,
                query_pairs,
                index,
                name,
                str(selected.get("variant", "")),
                str(selected.get("reason", "context_aware_mutation")),
            )
    return None


def build_all_contextual_diff_mutations(url: str) -> list[dict[str, Any]]:
    """Build contextual mutations for ALL meaningful parameters in a URL.

    Unlike build_contextual_diff_mutation which only mutates the first parameter,
    this generates mutations for every parameter that can produce payloads,
    enabling comprehensive coverage of multi-parameter URLs.

    Args:
        url: URL to mutate.

    Returns:
        List of dicts, each with mutated URL, parameter details, and mutation reason.
    """
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    mutations = []
    for index, (key, value) in enumerate(query_pairs):
        name = key.strip().lower()
        decoded = decode_candidate_value(value)
        if not name:
            continue
        payloads = generate_parameter_payloads(name, decoded, max_payloads_per_param=10)
        if payloads:
            selected = payloads[0]
            mutations.append(
                apply_query_pair_replacement(
                    parsed,
                    query_pairs,
                    index,
                    name,
                    str(selected.get("variant", "")),
                    str(selected.get("reason", "context_aware_mutation")),
                )
            )
    return mutations


def generate_contextual_payload_suggestions(
    priority_urls: list[str] | set[str], limit: int = 18
) -> list[dict[str, Any]]:
    """Generate contextual payload suggestions for priority URLs.

    Args:
        priority_urls: List of URLs to generate suggestions for.
        limit: Maximum number of suggestion entries to return.

    Returns:
        List of dicts with URL, endpoint key, and generated payloads.
    """
    suggestions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for url in priority_urls:
        if len(suggestions) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)
        generated = []
        for name, value in meaningful_query_pairs(url):
            generated.extend(list_contextual_parameter_payloads(name, value))
        if generated:
            suggestions.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "suggestions": generated[:40],
                }
            )
    return suggestions


def list_contextual_parameter_payloads(name: str, value: str) -> list[dict[str, Any]]:
    return generate_parameter_payloads(name, value, max_payloads_per_param=10)


def apply_query_pair_replacement(
    parsed: ParseResult,
    query_pairs: list[tuple[str, str]],
    index: int,
    parameter: str,
    value: str,
    strategy: str,
) -> dict[str, Any]:
    updated = list(query_pairs)
    updated[index] = (parameter, value)
    return {
        "parameter": parameter,
        "strategy": strategy,
        "mutated_url": normalize_url(
            urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
        ),
    }


def run_mutation_tests(
    urls: list[str],
    ranked_items: list[dict[str, Any]] | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Compatibility wrapper expected by active scan orchestrator."""
    candidates: list[str] = [str(value).strip() for value in (urls or []) if str(value).strip()]
    if not candidates and ranked_items:
        candidates = [
            str(item.get("url", "")).strip()
            for item in ranked_items
            if isinstance(item, dict) and str(item.get("url", "")).strip()
        ]

    if not candidates:
        return []

    suggestion_entries = generate_contextual_payload_suggestions(candidates, limit=limit)
    findings: list[dict[str, Any]] = []
    for entry in suggestion_entries:
        if len(findings) >= limit:
            break
        finding_url = str(entry.get("url", "")).strip()
        if not finding_url:
            continue
        suggestions = entry.get("suggestions", [])
        if not isinstance(suggestions, list) or not suggestions:
            continue
        findings.append(
            {
                "url": finding_url,
                "endpoint_key": entry.get("endpoint_key", endpoint_signature(finding_url)),
                "issues": ["mutation_payload_candidates"],
                "severity": "low",
                "confidence": 0.58,
                "suggestion_count": len(suggestions),
                "suggestions": suggestions[:10],
            }
        )
    return findings

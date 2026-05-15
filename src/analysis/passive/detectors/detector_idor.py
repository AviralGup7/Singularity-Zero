"""IDOR candidate finder for detecting Insecure Direct Object Reference patterns.

Analyzes URLs for numeric identifiers, UUIDs, object path keywords, and
parameter patterns that may indicate IDOR-vulnerable endpoints. Optionally
performs response comparison with mutated identifiers to confirm candidates.
"""

import re
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    classify_object_family,
    endpoint_base_key,
    endpoint_signature,
    is_low_value_endpoint,
    is_noise_url,
    is_self_endpoint,
    meaningful_query_pairs,
)
from src.analysis.intelligence.idor_mutations import (
    bulk_mutations,
    extract_path_identifier,
    generate_all_mutations,
    learn_id_pattern,
    relationship_hints,
)
from src.analysis.passive.patterns import IDOR_PARAM_NAMES, IDOR_PATH_KEYWORDS, UUID_RE
from src.analysis.passive.runtime import (
    ResponseCache,
    extract_key_fields,
    normalize_compare_text,
)

# Alias functions with underscore prefix for compatibility
_extract_path_identifier = extract_path_identifier
_learn_id_pattern = learn_id_pattern
_relationship_hints = relationship_hints
_bulk_mutations = bulk_mutations
_generate_all_mutations = generate_all_mutations


def idor_candidate_finder(
    urls: set[str],
    response_cache: ResponseCache | None = None,
    compare_enabled: bool = True,
    compare_limit: int = 12,
    similarity_threshold: float = 0.55,
) -> list[dict[str, Any]]:
    """Find potential IDOR candidates by analyzing URL patterns and parameters.

    Args:
        urls: Set of URLs to analyze.
        response_cache: Optional ResponseCache for response comparison.
        compare_enabled: Whether to perform response comparison mutations.
        compare_limit: Maximum number of comparisons to perform.
        similarity_threshold: Minimum body similarity to consider a match.

    Returns:
        List of IDOR candidate findings with signals, comparison data, and scores.
    """
    candidates: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()
    for raw_url in sorted(urls):
        if is_low_value_endpoint(raw_url) or is_noise_url(raw_url) or is_self_endpoint(raw_url):
            continue
        pattern_key = endpoint_signature(raw_url)
        if pattern_key in seen_patterns:
            continue
        seen_patterns.add(pattern_key)
        path = (urlparse(raw_url).path or "").lower()
        signals: list[str] = []

        if any(keyword in path for keyword in IDOR_PATH_KEYWORDS):
            signals.append("object_path_keyword")
        if re.search(r"/\d{2,}(?:/|$)", path):
            signals.append("numeric_path_identifier")
            # Check for nested resource IDOR (e.g., /users/123/orders/456)
            numeric_segments = re.findall(r"/(\d{2,})", path)
            if len(numeric_segments) >= 2:
                signals.append("nested_resource_idor")
        if UUID_RE.search(path):
            signals.append("uuid_path_identifier")
        # Check for path traversal patterns (e.g., /api/v1/users/../admin)
        if ".." in path or "%2e%2e" in path.lower():
            signals.append("path_traversal_in_url")
        # Check for batch/bulk operations with ID lists
        if any(kw in path for kw in ("/batch", "/bulk", "/batch-update", "/bulk-delete")):
            signals.append("batch_operation_endpoint")

        query_keys: list[str] = []
        has_numeric_identifier = False
        identifier_candidates: list[dict[str, Any]] = []
        for normalized_key, normalized_value in meaningful_query_pairs(raw_url):
            if normalized_key in IDOR_PARAM_NAMES:
                query_keys.append(normalized_key)
                if normalized_value.strip().isdigit():
                    signals.append(f"numeric_query_identifier:{normalized_key}")
                    has_numeric_identifier = True
                    identifier_candidates.append(
                        {
                            "location": "query",
                            "parameter": normalized_key,
                            "value": normalized_value.strip(),
                            "kind": "numeric",
                        }
                    )
                elif UUID_RE.search(normalized_value.strip()):
                    signals.append(f"uuid_query_identifier:{normalized_key}")
                    identifier_candidates.append(
                        {
                            "location": "query",
                            "parameter": normalized_key,
                            "value": normalized_value.strip(),
                            "kind": "uuid",
                        }
                    )
                else:
                    signals.append(f"object_reference_parameter:{normalized_key}")
                    identifier_candidates.append(
                        {
                            "location": "query",
                            "parameter": normalized_key,
                            "value": normalized_value.strip(),
                            "kind": "opaque",
                        }
                    )

        if "/api/" in path:
            signals.append("api_endpoint")
        path_identifier = _extract_path_identifier(path)
        if path_identifier:
            identifier_candidates.append(path_identifier)
        object_family = classify_object_family(raw_url)
        if object_family != "generic_object":
            signals.append(f"object_family:{object_family}")
        id_pattern = _learn_id_pattern(raw_url, identifier_candidates)
        rel_hints = _relationship_hints(raw_url, identifier_candidates)
        bulk_muts = _bulk_mutations(raw_url, identifier_candidates)
        if id_pattern != "unknown":
            signals.append(f"id_pattern:{id_pattern}")
        if rel_hints:
            signals.append("object_relationship_hint")
        if len(bulk_muts) >= 2:
            signals.append("bulk_id_mutation_ready")

        unique_signals = sorted(set(signals))
        score = len(unique_signals)
        has_uuid_identifier = any("uuid" in s for s in signals)
        has_opaque_identifier = any("object_reference_parameter" in s for s in signals)
        has_any_identifier = (
            has_numeric_identifier
            or has_uuid_identifier
            or has_opaque_identifier
            or bool(identifier_candidates)
        )
        if score < 2 or not has_any_identifier:
            continue

        candidates.append(
            {
                "url": raw_url,
                "endpoint_base_key": endpoint_base_key(raw_url),
                "endpoint_key": pattern_key,
                "endpoint_type": classify_endpoint(raw_url),
                "score": score,
                "signals": unique_signals,
                "query_keys": sorted(set(query_keys)),
                "object_family": object_family,
                "has_numeric_identifier": has_numeric_identifier,
                "has_uuid_identifier": has_uuid_identifier,
                "has_opaque_identifier": has_opaque_identifier,
                "identifier_candidates": identifier_candidates[:8],
                "id_pattern": id_pattern,
                "relationship_hints": rel_hints[:6],
                "bulk_mutations": bulk_muts[:6],
            }
        )

    candidates.sort(key=lambda item: (-item["score"], item["url"]))
    top_candidates = candidates[:150]
    if not compare_enabled or not response_cache:
        return top_candidates

    compared: list[dict[str, Any]] = []
    for item in top_candidates[:compare_limit]:
        comparison = _compare_idor_candidate_multi(
            item["url"], response_cache, similarity_threshold
        )
        if comparison:
            item["comparison"] = comparison
            item["score"] += comparison.get("confirmation_bonus", 2)
        compared.append(item)
    compared.extend(top_candidates[compare_limit:])
    compared.sort(key=lambda item: (-item["score"], item["url"]))
    return compared[:150]


def _compare_idor_candidate_multi(
    url: str, response_cache: ResponseCache, similarity_threshold: float
) -> dict[str, Any] | None:
    """Perform multiple mutation strategies for stronger IDOR confirmation.

    Tests several mutation strategies and aggregates results. A finding is
    confirmed when multiple mutations produce consistent response patterns.

    Args:
        url: Original URL to test.
        response_cache: ResponseCache for fetching mutated responses.
        similarity_threshold: Minimum body similarity to consider a match.

    Returns:
        Aggregated comparison dict with multi-strategy results, or None.
    """
    mutations = _generate_all_mutations(url)
    if not mutations:
        return None

    original_response = response_cache.get(url)
    if not original_response:
        return None

    original_body = original_response.get("body_text", "")
    original_body_normalized = normalize_compare_text(original_body)
    original_length = len(original_body)
    original_status = original_response.get("status_code")
    original_key_fields = extract_key_fields(original_body)
    results: list[dict[str, Any]] = []
    confirmed_count = 0

    for mutation in mutations[:4]:
        mutated_response = response_cache.get(mutation["mutated_url"])
        if not mutated_response:
            continue

        mutated_body = mutated_response.get("body_text", "")
        mutated_length = len(mutated_body)
        # Early exit: quick length check before expensive SequenceMatcher
        length_delta = abs(original_length - mutated_length)
        similar_length = length_delta <= max(120, int(max(original_length, 1) * 0.25))
        if not similar_length:
            # Still record the result but mark as unconfirmed
            results.append(  # type: ignore[reportUnknownMemberType]
                {
                    "mutated_url": mutated_response["url"],
                    "parameter": mutation.get("parameter", ""),
                    "strategy": mutation.get("strategy", ""),
                    "original_value": mutation.get("original_value", ""),
                    "mutated_value": mutation.get("mutated_value", ""),
                    "original_status": original_status,
                    "mutated_status": mutated_response.get("status_code"),
                    "body_similarity": 0.0,
                    "length_delta": length_delta,
                    "shared_key_fields": [],
                    "confirmed": False,
                }
            )
            continue

        mutated_status = mutated_response.get("status_code")
        same_status = original_status == mutated_status
        # Only run expensive SequenceMatcher when status matches and length is similar
        if same_status:
            similarity = round(
                SequenceMatcher(
                    None, original_body_normalized, normalize_compare_text(mutated_body)
                ).ratio(),
                3,
            )
        else:
            # Status changed - still compute similarity but it's less relevant
            similarity = round(
                SequenceMatcher(
                    None, original_body_normalized, normalize_compare_text(mutated_body)
                ).ratio(),
                3,
            )
        shared_keys = original_key_fields & extract_key_fields(mutated_body)

        is_confirmed = same_status and similar_length and similarity >= similarity_threshold
        if is_confirmed:
            confirmed_count += 1

        results.append(  # type: ignore[reportUnknownMemberType]
            {
                "mutated_url": mutated_response["url"],
                "parameter": mutation.get("parameter", ""),
                "strategy": mutation.get("strategy", ""),
                "original_value": mutation.get("original_value", ""),
                "mutated_value": mutation.get("mutated_value", ""),
                "original_status": original_status,
                "mutated_status": mutated_status,
                "body_similarity": similarity,
                "length_delta": length_delta,
                "shared_key_fields": sorted(shared_keys)[:12],
                "confirmed": is_confirmed,
            }
        )

    if not results:
        return None

    best_result: dict[str, Any] = max(
        results, key=lambda r: r.get("body_similarity", 0) if r.get("confirmed") else 0
    )
    confirmation_bonus = 2 + min(confirmed_count, 3)

    return {
        **best_result,
        "all_mutations_tested": len(results),
        "mutations_confirmed": confirmed_count,
        "confirmation_bonus": confirmation_bonus,
        "multi_strategy_confirmed": confirmed_count >= 2,
        "all_results": results,
    }

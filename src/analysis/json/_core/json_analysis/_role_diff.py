"""Role context diff and access control analysis."""

from difflib import SequenceMatcher
from typing import Any

from src.analysis.helpers import (
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.passive.runtime import normalize_compare_text

ROLE_PARAM_NAMES = {
    "role",
    "roles",
    "scope",
    "permission",
    "permissions",
    "tenant",
    "tenant_id",
    "account_id",
    "user_id",
    "admin",
}


def role_context_diff(responses: list[dict[str, Any]], limit: int = 50) -> list[dict[str, Any]]:
    """Compare responses across different role/tenant contexts."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url:
            continue
        query = dict(meaningful_query_pairs(url))
        if not any(
            key in query
            for key in (
                "role",
                "roles",
                "tenant",
                "tenant_id",
                "account_id",
                "user_id",
                "scope",
                "status",
            )
        ):
            continue
        grouped.setdefault(endpoint_base_key(url), []).append(response)

    findings: list[dict[str, Any]] = []
    for items in grouped.values():
        if len(items) < 2:
            continue
        items = sorted(items, key=lambda entry: entry.get("url", ""))
        original = items[0]
        original_body_normalized = normalize_compare_text(original.get("body_text") or "")
        original_url = str(original.get("url", ""))
        original_query_keys = set(dict(meaningful_query_pairs(original_url)))
        for candidate in items[1:]:
            if original.get("status_code") == candidate.get("status_code"):
                orig_len = len(original.get("body_text") or "")
                cand_len = len(candidate.get("body_text") or "")
                if abs(orig_len - cand_len) < max(20, int(orig_len * 0.02)):
                    candidate_body_normalized = normalize_compare_text(
                        candidate.get("body_text") or ""
                    )
                    if original_body_normalized == candidate_body_normalized:
                        continue
            similarity = round(
                SequenceMatcher(
                    None,
                    original_body_normalized,
                    normalize_compare_text(candidate.get("body_text") or ""),
                ).ratio(),
                3,
            )
            if original.get("status_code") == candidate.get("status_code") and similarity >= 0.98:
                continue
            candidate_url = str(candidate.get("url", ""))
            findings.append(
                {
                    "url": original_url,
                    "comparison_url": candidate_url,
                    "endpoint_key": endpoint_signature(original_url),
                    "endpoint_base_key": endpoint_base_key(original_url),
                    "status_pair": [original.get("status_code"), candidate.get("status_code")],
                    "body_similarity": similarity,
                    "context_keys": sorted(
                        original_query_keys.union(dict(meaningful_query_pairs(candidate_url)))
                    ),
                }
            )
    findings.sort(key=lambda item: (item["body_similarity"], item["url"]))
    return findings[:limit]


def cross_user_access_simulation(
    responses: list[dict[str, Any]], limit: int = 50
) -> list[dict[str, Any]]:
    """Simulate cross-user access by comparing responses with different identity contexts."""
    findings: list[dict[str, Any]] = []
    for item in role_context_diff(responses, limit=limit * 2):
        contexts = [
            value
            for value in item.get("context_keys", [])
            if value in {"user_id", "account_id", "tenant_id"}
        ]
        if not contexts:
            continue
        findings.append(
            {
                **item,
                "identity_contexts": contexts,
                "simulation_type": "same_endpoint_different_identity",
                "signals": ["identity_context_switch", "same_endpoint_comparison"],
            }
        )
    findings.sort(key=lambda item: (item["body_similarity"], item["url"]))
    return findings[:limit]


def role_based_endpoint_comparison(
    responses: list[dict[str, Any]], limit: int = 50
) -> list[dict[str, Any]]:
    """Compare endpoint responses across different role contexts."""
    findings: list[dict[str, Any]] = []
    for item in role_context_diff(responses, limit=limit * 2):
        contexts = {value for value in item.get("context_keys", []) if value in ROLE_PARAM_NAMES}
        if not contexts:
            continue
        status_pair = item.get("status_pair", [])
        body_similarity = float(item.get("body_similarity", 1.0) or 1.0)
        findings.append(
            {
                **item,
                "role_contexts": sorted(contexts),
                "signals": sorted(
                    {"role_context_switch"}
                    | (
                        {"status_divergence"}
                        if len(set(status_pair)) >= 2
                        else {"content_divergence"}
                    )
                ),
                "response_diff_strength": "high"
                if body_similarity < 0.6
                else "medium"
                if body_similarity < 0.9
                else "low",
            }
        )
    findings.sort(
        key=lambda item: (
            item["response_diff_strength"] != "high",
            item["body_similarity"],
            item["url"],
        )
    )
    return findings[:limit]

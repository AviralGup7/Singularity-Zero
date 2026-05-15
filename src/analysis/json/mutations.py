"""URL mutation helpers for JSON analysis.

Contains functions for mutating URLs to test pagination, filters, error probes,
role changes, state transitions, and dependency parameters.
Extracted from json_analysis_support.py for better separation of concerns.
"""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import decode_candidate_value
from src.analysis.passive.patterns import UUID_RE
from src.recon.common import normalize_url

from ._constants import (
    DEPENDENCY_PARAM_NAMES,
    FILTER_MUTATIONS,
    PAGINATION_PARAM_NAMES,
    ROLE_MUTATION_PARAM_NAMES,
    STATE_PARAM_NAMES,
)

__all__ = [
    "alternate_version_url",
    "mutate_dependency_urls",
    "mutate_error_probe_url",
    "mutate_filter_url",
    "mutate_pagination_url",
    "mutate_role_url",
    "mutate_state_url",
    "replace_query_pair",
]


def replace_query_pair(
    parsed: Any, query_pairs: list[tuple[str, str]], index: int, parameter: str, value: str
) -> dict[str, Any]:
    updated = list(query_pairs)
    original_value = updated[index][1]
    updated[index] = (updated[index][0], value)
    return {
        "parameter": parameter,
        "original_value": original_value,
        "mutated_value": value,
        "mutated_url": normalize_url(
            urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
        ),
    }


def mutate_pagination_url(url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_map = dict(query_pairs)
    for index, (key, value) in enumerate(query_pairs):
        lowered = key.strip().lower()
        if lowered not in PAGINATION_PARAM_NAMES:
            continue
        decoded = decode_candidate_value(value)
        if lowered == "page" and decoded.isdigit():
            return replace_query_pair(
                parsed, query_pairs, index, lowered, str(max(2, int(decoded) + 1))
            )
        if lowered in {"offset"} and decoded.isdigit():
            step = (
                int(query_map.get("limit", "10"))
                if str(query_map.get("limit", "")).isdigit()
                else 10
            )
            return replace_query_pair(parsed, query_pairs, index, lowered, str(int(decoded) + step))
        if lowered in {"limit", "per_page", "page_size"} and decoded.isdigit():
            return replace_query_pair(
                parsed,
                query_pairs,
                index,
                lowered,
                str(min(max(int(decoded) * 2, int(decoded) + 10), 100)),
            )
    return None


def mutate_filter_url(url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for index, (key, value) in enumerate(query_pairs):
        lowered = key.strip().lower()
        if lowered in FILTER_MUTATIONS:
            return replace_query_pair(
                parsed, query_pairs, index, lowered, FILTER_MUTATIONS[lowered]
            )
    return None


def mutate_error_probe_url(url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for index, (key, value) in enumerate(query_pairs):
        lowered = key.strip().lower()
        decoded = decode_candidate_value(value)
        if decoded.isdigit():
            return replace_query_pair(parsed, query_pairs, index, lowered, "not-a-number")
        if UUID_RE.search(decoded):
            return replace_query_pair(
                parsed, query_pairs, index, lowered, "00000000-0000-4000-8000-000000000000"
            )
        if lowered not in PAGINATION_PARAM_NAMES:
            return replace_query_pair(parsed, query_pairs, index, lowered, "__invalid__")
    return None


def alternate_version_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path
    if "/v1/" in path:
        return normalize_url(urlunparse(parsed._replace(path=path.replace("/v1/", "/v2/", 1))))
    if "/v2/" in path:
        return normalize_url(urlunparse(parsed._replace(path=path.replace("/v2/", "/v1/", 1))))
    return ""


def mutate_role_url(url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for index, (key, value) in enumerate(query_pairs):
        lowered = key.strip().lower()
        if lowered not in ROLE_MUTATION_PARAM_NAMES:
            continue
        updated = list(query_pairs)
        current_value = decode_candidate_value(value).lower()
        if current_value in {"", "true", "1"}:
            mutated_value = "false" if lowered == "admin" else "user"
        else:
            mutated_value = "admin" if current_value != "admin" else "user"
        updated[index] = (key, mutated_value)
        return {
            "parameter": lowered,
            "original_value": decode_candidate_value(value),
            "mutated_value": mutated_value,
            "mutated_url": normalize_url(
                urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            ),
        }
    return None


def mutate_state_url(url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    state_mutations = {
        "pending": "approved",
        "draft": "published",
        "cart": "paid",
        "review": "complete",
        "false": "true",
        "0": "1",
    }
    for index, (key, value) in enumerate(query_pairs):
        lowered = key.strip().lower()
        decoded = decode_candidate_value(value).lower()
        if lowered not in STATE_PARAM_NAMES:
            continue
        mutated_value = state_mutations.get(decoded, "approved")
        updated = list(query_pairs)
        updated[index] = (key, mutated_value)
        return {
            "parameter": lowered,
            "original_value": decode_candidate_value(value),
            "mutated_value": mutated_value,
            "mutated_url": normalize_url(
                urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            ),
        }
    return None


def mutate_dependency_urls(url: str) -> list[dict[str, Any]]:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    mutations: list[dict[str, Any]] = []
    for index, (key, value) in enumerate(query_pairs):
        lowered = key.strip().lower()
        if lowered not in DEPENDENCY_PARAM_NAMES:
            continue
        decoded = decode_candidate_value(value)
        mutated_value = decoded
        if decoded.isdigit():
            mutated_value = str(max(1, int(decoded) * 2))
        elif lowered in {"role", "roles", "permission", "permissions", "scope"}:
            mutated_value = "admin"
        elif lowered in {"currency"}:
            mutated_value = "USD" if decoded.upper() != "USD" else "EUR"
        elif lowered in {"coupon", "promo", "discount"}:
            mutated_value = "FREE100"
        if mutated_value == decoded:
            continue
        updated = list(query_pairs)
        updated[index] = (key, mutated_value)
        mutations.append(
            {
                "parameter": lowered,
                "original_value": decoded,
                "mutated_value": mutated_value,
                "mutated_url": normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                ),
            }
        )
    return mutations

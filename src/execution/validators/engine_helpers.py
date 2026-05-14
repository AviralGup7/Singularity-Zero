"""Helper utilities for the validation engine.

Contains scope checking, URL mutation, response comparison, and token replay
summary functions. Extracted from engine.py for better separation of concerns.
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.core.contracts.pipeline import scope_match
from src.execution.validators.validators.token import analyze_token_exposures


def collect_scope_hosts(
    analysis_results: dict[str, list[dict[str, Any]]],
    ranked_priority_urls: list[dict[str, Any]],
    runtime_inputs: dict[str, Any],
) -> set[str]:
    """Collect scope hosts from runtime inputs or fallback to analysis results."""
    hosts: set[str] = set()
    for url in runtime_inputs.get("urls", []) or []:
        host = (urlparse(str(url)).hostname or "").lower()
        if host:
            hosts.add(host)
    for response in runtime_inputs.get("responses", []) or []:
        host = (urlparse(str(response.get("url", ""))).hostname or "").lower()
        if host:
            hosts.add(host)
    if hosts:
        return hosts

    # Fallback for legacy flows that do not pass runtime URL scope inputs.
    for item in ranked_priority_urls:
        host = (urlparse(str(item.get("url", ""))).hostname or "").lower()
        if host:
            hosts.add(host)
    for key in ("idor_candidate_finder", "ssrf_candidate_finder"):
        for item in analysis_results.get(key, []):
            host = (urlparse(str(item.get("url", ""))).hostname or "").lower()
            if host:
                hosts.add(host)
    return hosts


def scope_check(url: str, scope_hosts: set[str]) -> tuple[bool, str]:
    """Check if a URL is within scope."""
    return scope_match(url, scope_hosts)


def mutate_identifier(url: str) -> str:
    """Generate a mutated URL with a modified identifier for IDOR testing.

    Supports multiple identifier formats:
    - Numeric IDs: increment by 1
    - UUIDs: flip last hex digit
    - String IDs: append/remove suffix, change case
    - Path-based IDs: same mutations applied to path segments
    """
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    # Strategy 1: Numeric ID mutation in query parameters
    for index, (key, value) in enumerate(query_pairs):
        trimmed = value.strip()
        if trimmed.isdigit():
            updated = list(query_pairs)
            updated[index] = (key, str(int(trimmed) + 1))
            return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    # Strategy 2: UUID mutation in query parameters
    uuid_pattern = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    for index, (key, value) in enumerate(query_pairs):
        trimmed = value.strip()
        if uuid_pattern.match(trimmed):
            updated = list(query_pairs)
            last_char = trimmed[-1]
            flipped = "0" if last_char != "0" else "1"
            mutated_uuid = trimmed[:-1] + flipped
            updated[index] = (key, mutated_uuid)
            return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    # Strategy 3: String ID mutation in query parameters
    for index, (key, value) in enumerate(query_pairs):
        trimmed = value.strip()
        if trimmed and not trimmed.isdigit() and not uuid_pattern.match(trimmed):
            updated = list(query_pairs)
            if trimmed.endswith("_test") or trimmed.endswith("_prod"):
                suffix = "_prod" if trimmed.endswith("_test") else "_test"
                updated[index] = (key, trimmed[:-5] + suffix)
            elif len(trimmed) >= 3:
                updated[index] = (key, trimmed + "1")
            else:
                updated[index] = (key, trimmed.upper() if trimmed.islower() else trimmed.lower())
            return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

    # Strategy 4: Numeric ID mutation in path segments
    path = parsed.path or ""
    for index in range(len(path) - 1, -1, -1):
        if not path[index].isdigit():
            continue
        start = index
        while start > 0 and path[start - 1].isdigit():
            start -= 1
        segment = path[start : index + 1]
        if len(segment) >= 2:
            bumped = f"{path[:start]}{int(segment) + 1}{path[index + 1 :]}"
            return urlunparse(parsed._replace(path=bumped))
        break

    # Strategy 5: UUID in path segments
    path_segments = path.strip("/").split("/")
    for i, segment in enumerate(reversed(path_segments)):
        if uuid_pattern.match(segment):
            last_char = segment[-1]
            flipped = "0" if last_char != "0" else "1"
            mutated_uuid = segment[:-1] + flipped
            new_segments = path_segments.copy()
            new_segments[len(path_segments) - 1 - i] = mutated_uuid
            return urlunparse(parsed._replace(path="/" + "/".join(new_segments)))
        break

    return ""


def compare_response_shapes(original: dict[str, Any], variant: dict[str, Any]) -> str:
    """Compare two HTTP responses to determine if they indicate an IDOR vulnerability.

    Returns a classification string:
    - "potential_idor": Responses differ significantly
    - "response_similarity_match": Responses are similar
    - "observed_behavior_change": Responses differ in expected way
    """
    same_status = original.get("status_code") == variant.get("status_code")
    original_len = int(original.get("body_length", 0) or 0)
    variant_len = int(variant.get("body_length", 0) or 0)
    max_len = max(1, original_len)
    close_length = abs(original_len - variant_len) <= max(120, int(max_len * 0.25))

    orig_status = int(original.get("status_code", 0) or 0)
    var_status = int(variant.get("status_code", 0) or 0)
    if orig_status == 200 and var_status in {401, 403, 404}:
        return "observed_behavior_change"
    if orig_status in {401, 403} and var_status == 200:
        return "potential_idor"
    if same_status and not close_length:
        return "potential_idor"
    if same_status and close_length:
        return "response_similarity_match"
    if orig_status >= 400 and var_status >= 400:
        return "observed_behavior_change"
    return "observed_behavior_change"


def build_token_replay_summary(analysis_results: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Build a summary of token replay analysis."""
    return analyze_token_exposures(analysis_results)


def selector_params(extra: dict[str, Any]) -> list[str]:
    """Extract parameter names from validator extra data."""
    params: list[str] = []
    for key in ("parameters", "matched_parameters", "query_keys"):
        values = extra.get(key, [])
        if isinstance(values, list):
            params.extend(str(value) for value in values if str(value).strip())
    return sorted({value.strip().lower() for value in params if value.strip()})

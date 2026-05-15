"""IDOR mutation generators and pattern extraction utilities.

Contains functions for generating IDOR test mutations, extracting path
identifiers, learning ID patterns, and bulk mutation generation.
Extracted from passive_detector_idor.py for better separation of concerns.
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import meaningful_query_pairs
from src.analysis.passive.patterns import UUID_RE
from src.recon.common import normalize_url


def generate_all_mutations(url: str) -> list[dict[str, Any]]:
    """Generate multiple mutation strategies for a URL."""
    mutations: list[dict[str, Any]] = []
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    for index, (key, value) in enumerate(query_pairs):
        normalized_value = value.strip()
        if normalized_value.isdigit():
            num = int(normalized_value)
            strategies = [
                ("numeric_query_increment", str(num + 1)),
                ("numeric_query_decrement", str(max(0, num - 1))),
                ("numeric_query_zero", "0"),
                ("numeric_query_large", str(num + 1000)),
            ]
            for strategy_name, mutated_value in strategies:
                updated = list(query_pairs)
                updated[index] = (key, mutated_value)
                mutations.append(
                    {
                        "parameter": key,
                        "strategy": strategy_name,
                        "original_value": normalized_value,
                        "mutated_value": mutated_value,
                        "mutated_url": normalize_url(
                            urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                        ),
                    }
                )
        elif UUID_RE.search(normalized_value):
            for mutated_value, strategy_name in [
                ("00000000-0000-4000-8000-000000000000", "uuid_query_null"),
                ("11111111-1111-4111-8111-111111111111", "uuid_query_alternative"),
                ("ffffffff-ffff-4fff-8fff-ffffffffffff", "uuid_query_max"),
            ]:
                if mutated_value.lower() == normalized_value.lower():
                    continue
                updated = list(query_pairs)
                updated[index] = (key, mutated_value)
                mutations.append(
                    {
                        "parameter": key,
                        "strategy": strategy_name,
                        "original_value": normalized_value,
                        "mutated_value": mutated_value,
                        "mutated_url": normalize_url(
                            urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                        ),
                    }
                )

    path = parsed.path or ""
    path_segments = path.strip("/").split("/")
    for seg_idx, segment in enumerate(path_segments):
        if re.match(r"^v\d+$", segment, re.IGNORECASE):
            continue
        if re.match(r"^\d{2,}$", segment):
            num = int(segment)
            path_prefix = "/" + "/".join(path_segments[:seg_idx]) + "/"
            path_suffix = (
                "/" + "/".join(path_segments[seg_idx + 1 :])
                if seg_idx < len(path_segments) - 1
                else ""
            )
            if not path_suffix and seg_idx == len(path_segments) - 1:
                path_suffix = ""
            for strategy_name, mutated_value in [
                ("numeric_path_increment", str(num + 1)),
                ("numeric_path_decrement", str(max(0, num - 1))),
                ("numeric_path_zero", "0"),
                ("numeric_path_large", str(num + 1000)),
            ]:
                updated_path = f"{path_prefix}{mutated_value}{path_suffix}"
                mutations.append(
                    {
                        "parameter": f"path_segment_{seg_idx}",
                        "strategy": strategy_name,
                        "original_value": segment,
                        "mutated_value": mutated_value,
                        "mutated_url": normalize_url(
                            urlunparse(parsed._replace(path=updated_path))
                        ),
                    }
                )

    uuid_match = UUID_RE.search(path)
    if uuid_match:
        original_value = uuid_match.group(0)
        for mutated_value, strategy_name in [
            ("00000000-0000-4000-8000-000000000000", "uuid_path_null"),
            ("11111111-1111-4111-8111-111111111111", "uuid_path_alternative"),
        ]:
            if mutated_value.lower() == original_value.lower():
                continue
            updated_path = f"{path[: uuid_match.start()]}{mutated_value}{path[uuid_match.end() :]}"
            mutations.append(
                {
                    "parameter": "path",
                    "strategy": strategy_name,
                    "original_value": original_value,
                    "mutated_value": mutated_value,
                    "mutated_url": normalize_url(urlunparse(parsed._replace(path=updated_path))),
                }
            )

    return mutations


def mutate_identifier(url: str) -> dict[str, Any] | None:
    """Generate a single identifier mutation for a URL."""
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for index, (key, value) in enumerate(query_pairs):
        normalized_value = value.strip()
        if normalized_value.isdigit():
            updated = list(query_pairs)
            mutated_value = str(int(normalized_value) + 1)
            updated[index] = (key, mutated_value)
            return {
                "parameter": key,
                "strategy": "numeric_query_increment",
                "original_value": normalized_value,
                "mutated_value": mutated_value,
                "mutated_url": normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                ),
            }
        if UUID_RE.search(normalized_value):
            mutated_value = "00000000-0000-4000-8000-000000000000"
            if mutated_value.lower() == normalized_value.lower():
                mutated_value = "11111111-1111-4111-8111-111111111111"
            updated = list(query_pairs)
            updated[index] = (key, mutated_value)
            return {
                "parameter": key,
                "strategy": "uuid_query_replace",
                "original_value": normalized_value,
                "mutated_value": mutated_value,
                "mutated_url": normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                ),
            }

    path = parsed.path or ""
    match = re.search(r"(\d{2,})(?!.*\d)", path)
    if match:
        original_value = match.group(1)
        mutated_value = str(int(original_value) + 1)
        updated_path = f"{path[: match.start(1)]}{mutated_value}{path[match.end(1) :]}"
        return {
            "parameter": "path",
            "strategy": "numeric_path_increment",
            "original_value": original_value,
            "mutated_value": mutated_value,
            "mutated_url": normalize_url(urlunparse(parsed._replace(path=updated_path))),
        }
    uuid_match = UUID_RE.search(path)
    if uuid_match:
        original_value = uuid_match.group(0)
        mutated_value = "00000000-0000-4000-8000-000000000000"
        if mutated_value.lower() == original_value.lower():
            mutated_value = "11111111-1111-4111-8111-111111111111"
        updated_path = f"{path[: uuid_match.start()]}{mutated_value}{path[uuid_match.end() :]}"
        return {
            "parameter": "path",
            "strategy": "uuid_path_replace",
            "original_value": original_value,
            "mutated_value": mutated_value,
            "mutated_url": normalize_url(urlunparse(parsed._replace(path=updated_path))),
        }
    return None


def extract_path_identifier(path: str) -> dict[str, Any] | None:
    match = re.search(r"(\d{2,})(?!.*\d)", path)
    if match:
        return {"location": "path", "parameter": "path", "value": match.group(1), "kind": "numeric"}
    uuid_match = UUID_RE.search(path)
    if uuid_match:
        return {
            "location": "path",
            "parameter": "path",
            "value": uuid_match.group(0),
            "kind": "uuid",
        }
    return None


def learn_id_pattern(url: str, identifier_candidates: list[dict[str, Any]]) -> str:
    values = [
        str(item.get("value", "")).strip() for item in identifier_candidates if item.get("value")
    ]
    if any(value.isdigit() for value in values):
        return "sequential_numeric"
    if any(UUID_RE.search(value) for value in values):
        return "uuid"
    path = urlparse(url).path.lower()
    if re.search(r"/[a-z]+-\d+(?:/|$)", path):
        return "prefixed_numeric"
    return "unknown"


def relationship_hints(url: str, identifier_candidates: list[dict[str, Any]]) -> list[str]:
    keys = [name for name, _ in meaningful_query_pairs(url)]
    relationships = []
    if {"user_id", "account_id"} & set(keys):
        relationships.append("user_to_account")
    if {"user_id", "resource_id"} & set(keys):
        relationships.append("user_to_resource")
    if {"tenant_id", "user_id"} & set(keys):
        relationships.append("tenant_to_user")
    if {"project_id", "member_id"} & set(keys):
        relationships.append("project_to_member")
    if len(identifier_candidates) >= 2:
        relationships.append("multi_identifier_endpoint")
    return sorted(set(relationships))


def bulk_mutations(
    url: str, identifier_candidates: list[dict[str, Any]], top_n: int = 5
) -> list[dict[str, Any]]:
    variants: list[dict[str, Any]] = []
    for candidate in identifier_candidates:
        parameter = str(candidate.get("parameter", "path"))
        value = str(candidate.get("value", "")).strip()
        kind = str(candidate.get("kind", "opaque"))
        if kind == "numeric" and value.isdigit():
            numeric_value = int(value)
            for next_value in [
                max(1, numeric_value - 1),
                numeric_value + 1,
                numeric_value + 2,
                max(1, numeric_value + 10),
            ]:
                mutated = replace_identifier(
                    url,
                    parameter,
                    value,
                    str(next_value),
                    location=str(candidate.get("location", "query")),
                )
                if mutated:
                    variants.append(
                        {
                            "parameter": parameter,
                            "original_value": value,
                            "mutated_value": str(next_value),
                            "mutated_url": mutated,
                        }
                    )
        elif kind == "uuid":
            for uuid_val in [
                "00000000-0000-4000-8000-000000000000",
                "11111111-1111-4111-8111-111111111111",
            ]:
                mutated = replace_identifier(
                    url,
                    parameter,
                    value,
                    uuid_val,
                    location=str(candidate.get("location", "query")),
                )
                if mutated:
                    variants.append(
                        {
                            "parameter": parameter,
                            "original_value": value,
                            "mutated_value": uuid_val,
                            "mutated_url": mutated,
                        }
                    )
    deduped = []
    seen: set[str] = set()
    for item in variants:
        if item["mutated_url"] in seen:
            continue
        seen.add(item["mutated_url"])
        deduped.append(item)
    return deduped[:top_n]


def replace_identifier(
    url: str, parameter: str, original_value: str, mutated_value: str, *, location: str
) -> str:
    parsed = urlparse(url)
    if location == "path":
        path = parsed.path or ""
        if original_value not in path:
            return ""
        updated_path = path.replace(original_value, mutated_value, 1)
        return normalize_url(urlunparse(parsed._replace(path=updated_path)))
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = []
    found = False
    for key, value in query_pairs:
        if key == parameter and value == original_value and not found:
            updated.append((key, mutated_value))
            found = True
        else:
            updated.append((key, value))
    if not found:
        return ""
    return normalize_url(urlunparse(parsed._replace(query=urlencode(updated, doseq=True))))

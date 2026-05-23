"""POST body inference and mutation attacks."""

import json
from typing import Any

from src.analysis.helpers import (
    AUTH_SKIP_PARAMS,
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache

from .diff import _variant_diff_summary


def _infer_body_fields(body_text: str) -> list[tuple[str, str]]:
    """Infer JSON body fields from response text."""
    try:
        data = json.loads(body_text)
    except json.JSONDecodeError, ValueError:
        return []
    if not isinstance(data, dict):
        return []
    fields: list[tuple[str, str]] = []
    for key, value in data.items():
        if isinstance(value, bool):
            fields.append((key, "boolean"))
        elif isinstance(value, int):
            fields.append((key, "integer"))
        elif isinstance(value, float):
            fields.append((key, "float"))
        elif isinstance(value, str):
            fields.append((key, "string"))
        elif isinstance(value, list):
            fields.append((key, "array"))
        elif isinstance(value, dict):
            fields.append((key, "object"))
        elif value is None:
            fields.append((key, "null"))
        else:
            fields.append((key, "unknown"))
    return fields


def _post_body_mutations(field_name: str, field_type: str) -> list[dict[str, Any]]:
    """Generate POST body mutation strategies for a given field."""
    mutations: list[dict[str, Any]] = []
    lowered = field_name.lower()
    if field_type == "integer":
        mutations.append(
            {"strategy": "type_confusion_string", "body": {field_name: "not_a_number"}}
        )
        mutations.append({"strategy": "null_injection", "body": {field_name: None}})
        mutations.append({"strategy": "integer_overflow", "body": {field_name: 9999999999999999}})
    elif field_type == "string":
        mutations.append({"strategy": "type_confusion_number", "body": {field_name: 0}})
        mutations.append({"strategy": "null_injection", "body": {field_name: None}})
        if lowered in {"role", "roles", "scope", "permission", "permissions"}:
            mutations.append({"strategy": "privilege_escalation", "body": {field_name: "admin"}})
    elif field_type == "boolean":
        mutations.append({"strategy": "type_confusion_string", "body": {field_name: "true"}})
        mutations.append({"strategy": "null_injection", "body": {field_name: None}})
    elif field_type in ("object", "array"):
        mutations.append(
            {"strategy": "type_confusion_string", "body": {field_name: "string_replacement"}}
        )
        mutations.append({"strategy": "null_injection", "body": {field_name: None}})
    mutations.append({"strategy": "prototype_pollution", "body": {"__proto__": {"polluted": True}}})
    return mutations


def post_body_mutation_attacks(
    priority_urls: list[str],
    response_cache: ResponseCache,
    limit: int = 16,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url) or classify_endpoint(url) == "STATIC":
            continue
        baseline = response_cache.get(url)
        if not baseline:
            continue
        ct = str(baseline.get("content_type", "")).lower()
        if classify_endpoint(url) != "API" and "json" not in ct:
            continue
        body_text = baseline.get("body_text") or ""
        inferred_fields = _infer_body_fields(body_text)
        if not inferred_fields:
            continue
        observations = []
        for field_name, field_type in inferred_fields[:5]:
            if field_name.lower() in AUTH_SKIP_PARAMS:
                continue
            mutations = _post_body_mutations(field_name, field_type)
            for mutation in mutations[:3]:
                mutated_body = json.dumps(mutation["body"], ensure_ascii=False)
                mutated = response_cache.request(
                    url,
                    method="POST",
                    headers={
                        "Cache-Control": "no-cache",
                        "Content-Type": "application/json",
                        "X-POST-Mutation": mutation["strategy"],
                    },
                    body=mutated_body,
                )
                if not mutated:
                    continue
                diff = _variant_diff_summary(baseline, mutated)
                if not (
                    diff["changed"] or diff["status_changed"] or diff["body_similarity"] < 0.95
                ):
                    continue
                observations.append(
                    {
                        "field": field_name,
                        "original_type": field_type,
                        "strategy": mutation["strategy"],
                        "mutated_body_sample": mutated_body[:120],
                        **diff,
                    }
                )
        if observations:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "content_type": baseline.get("content_type", ""),
                    "observations": observations[:4],
                    "signals": sorted(
                        {
                            "post_body_mutation",
                            "status_divergence"
                            if any(i["status_changed"] for i in observations)
                            else "",
                            "content_divergence"
                            if any(i["content_changed"] for i in observations)
                            else "",
                            "type_confusion"
                            if any("type_confusion" in i.get("strategy", "") for i in observations)
                            else "",
                            "null_injection"
                            if any("null_injection" in i.get("strategy", "") for i in observations)
                            else "",
                            "prototype_pollution"
                            if any(
                                "prototype_pollution" in i.get("strategy", "") for i in observations
                            )
                            else "",
                        }
                        - {""}
                    ),
                }
            )
    findings.sort(key=lambda i: (-len(i["observations"]), i["url"]))
    return findings[:limit]

"""JSON response parsing and schema inference."""

from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.json.support import (
    ID_FIELD_RE,
    ROLE_FIELD_TOKENS,
    SENSITIVE_FIELD_TOKENS,
    parse_json_payload,
    summarize_json_payload,
)


def json_response_parser(responses: list[dict[str, Any]], limit: int = 120) -> list[dict[str, Any]]:
    """Parse JSON responses and extract structural information."""
    parsed_items: list[dict[str, Any]] = []
    for response in responses:
        payload = parse_json_payload(response)
        if payload is None:
            continue
        summary = summarize_json_payload(payload)
        url = str(response.get("url", "")).strip()
        parsed_items.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "status_code": response.get("status_code"),
                "top_level_type": summary["top_level_type"],
                "top_level_keys": summary["top_level_keys"][:12],
                "field_count": summary["field_count"],
                "max_depth": summary["max_depth"],
                "object_count": summary["object_count"],
                "array_count": summary["array_count"],
                "id_fields": summary["id_fields"][:12],
                "nested_paths": summary["nested_paths"][:10],
                "key_fields": sorted(summary["field_names"])[:16],
            }
        )
    parsed_items.sort(key=lambda item: (-item["max_depth"], -item["field_count"], item["url"]))
    return parsed_items[:limit]


def json_schema_inference(responses: list[dict[str, Any]], limit: int = 80) -> list[dict[str, Any]]:
    """Infer JSON schema across multiple responses."""
    field_map: dict[str, dict[str, Any]] = {}
    parsed_cache: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for response in responses:
        payload = parse_json_payload(response)
        if payload is None:
            continue
        summary = summarize_json_payload(payload)
        parsed_cache.append((response, summary))
    for response, summary in parsed_cache:
        for field_name, info in summary["fields"].items():
            entry = field_map.setdefault(
                field_name,
                {
                    "field_name": field_name,
                    "types": set(),
                    "occurrences": 0,
                    "sample_paths": set(),
                    "example_urls": set(),
                    "id_like": bool(ID_FIELD_RE.search(field_name)),
                    "role_like": any(token in field_name for token in ROLE_FIELD_TOKENS),
                    "sensitive_like": any(token in field_name for token in SENSITIVE_FIELD_TOKENS),
                },
            )
            entry["types"].update(info["types"])
            entry["occurrences"] += info["occurrences"]
            entry["sample_paths"].update(info["paths"])
            entry["example_urls"].add(str(response.get("url", "")))
    results = []
    for entry in field_map.values():
        results.append(
            {
                "field_name": entry["field_name"],
                "types": sorted(entry["types"]),
                "occurrences": entry["occurrences"],
                "sample_paths": sorted(entry["sample_paths"])[:6],
                "example_urls": sorted(entry["example_urls"])[:4],
                "id_like": entry["id_like"],
                "role_like": entry["role_like"],
                "sensitive_like": entry["sensitive_like"],
            }
        )
    results.sort(
        key=lambda item: (
            not (item["id_like"] or item["role_like"] or item["sensitive_like"]),
            -item["occurrences"],
            item["field_name"],
        )
    )
    return results[:limit]


def sensitive_field_detector(
    responses: list[dict[str, Any]], limit: int = 80
) -> list[dict[str, Any]]:
    """Detect sensitive fields in JSON responses."""
    findings: list[dict[str, Any]] = []
    for response in responses:
        payload = parse_json_payload(response)
        if payload is None:
            continue
        summary = summarize_json_payload(payload)
        matched = []
        for hit in summary["sensitive_fields"]:
            matched.append(
                {
                    "field": hit["field"],
                    "path": hit["path"],
                    "classification": hit["classification"],
                }
            )
        if not matched:
            continue
        url = str(response.get("url", "")).strip()
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "status_code": response.get("status_code"),
                "matched_fields": matched[:12],
                "field_count": len(matched),
            }
        )
    findings.sort(key=lambda item: (-item["field_count"], item["url"]))
    return findings[:limit]


def cross_tenant_pii_risk_analyzer(
    responses: list[dict[str, Any]], limit: int = 60
) -> list[dict[str, Any]]:
    """Analyze cross-tenant PII risk in JSON responses."""
    findings: list[dict[str, Any]] = []
    for response in responses:
        payload = parse_json_payload(response)
        if payload is None:
            continue
        summary = summarize_json_payload(payload)
        field_names = summary["field_names"]
        identity_fields = sorted(
            field
            for field in field_names
            if field in {"tenant", "tenant_id", "account_id", "user_id", "org_id"}
        )
        pii_fields = sorted(
            {
                item["field"]
                for item in summary["sensitive_fields"]
                if item["classification"] in {"email", "ssn", "credential", "api_key"}
            }
        )
        if not identity_fields or not pii_fields:
            continue
        url = str(response.get("url", "")).strip()
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "status_code": response.get("status_code"),
                "identity_fields": identity_fields,
                "pii_fields": pii_fields,
                "collection_like": summary["array_count"] > 0 or summary["object_count"] >= 3,
                "max_depth": summary["max_depth"],
                "matched_paths": sorted(
                    {
                        item["path"]
                        for item in summary["sensitive_fields"]
                        if item["field"] in pii_fields
                    }
                )[:10],
            }
        )
    findings.sort(
        key=lambda item: (not item["collection_like"], -len(item["pii_fields"]), item["url"])
    )
    return findings[:limit]


def nested_object_traversal(
    responses: list[dict[str, Any]], limit: int = 60
) -> list[dict[str, Any]]:
    """Analyze deeply nested JSON object structures."""
    findings: list[dict[str, Any]] = []
    for response in responses:
        payload = parse_json_payload(response)
        if payload is None:
            continue
        summary = summarize_json_payload(payload)
        score = (
            summary["max_depth"] * 3
            + summary["object_count"]
            + summary["array_count"]
            + len(summary["id_fields"]) * 2
        )
        if score < 8:
            continue
        url = str(response.get("url", "")).strip()
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "status_code": response.get("status_code"),
                "traversal_score": score,
                "max_depth": summary["max_depth"],
                "object_count": summary["object_count"],
                "array_count": summary["array_count"],
                "id_fields": summary["id_fields"][:10],
                "nested_paths": summary["nested_paths"][:10],
            }
        )
    findings.sort(key=lambda item: (-item["traversal_score"], item["url"]))
    return findings[:limit]

"""Detection utilities for tenant parameter identification."""

import json
from typing import Any

from .constants import TENANT_PARAM_NAMES


def _extract_json(body: str) -> dict | list | None:
    stripped = body.strip()
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(stripped[:50000])  # type: ignore
        except json.JSONDecodeError, ValueError:
            return None
    return None


def _extract_tenant_from_json(data: Any, depth: int = 0) -> list[dict[str, str]]:
    if depth > 5:
        return []
    results = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key.lower() in TENANT_PARAM_NAMES and isinstance(value, (str, int)):
                results.append({"parameter": key, "value": str(value), "location": "json_body"})
            elif isinstance(value, (dict, list)):
                results.extend(_extract_tenant_from_json(value, depth + 1))
    elif isinstance(data, list):
        for item in data[:10]:
            if isinstance(item, (dict, list)):
                results.extend(_extract_tenant_from_json(item, depth + 1))
    return results


def detect_tenant_parameters(urls: list, responses: list) -> dict:
    """Detect tenant-related parameters in URLs and responses.

    Scans URL query parameters, path segments, response headers, and
    response bodies for tenant identifiers used in multi-tenant applications.

    Args:
        urls: List of URL strings or URL dicts to analyze.
        responses: List of response dicts to scan for tenant indicators.

    Returns:
        Dict with detected tenant parameters organized by location.
    """
    from urllib.parse import parse_qsl, urlparse

    from .constants import MULTI_TENANT_INDICATORS, TENANT_HEADER_NAMES, TENANT_PATH_PATTERN

    result: dict[str, Any] = {
        "query_params": [],
        "headers": [],
        "path_params": [],
        "json_fields": [],
        "multi_tenant_detected": False,
        "tenant_params": set(),
    }

    for url_entry in urls:
        url = str(
            url_entry.get("url", url_entry) if isinstance(url_entry, dict) else url_entry
        ).strip()
        if not url:
            continue
        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for key, value in query_pairs:
            if key.lower() in TENANT_PARAM_NAMES:
                result["query_params"].append({"parameter": key, "value": value, "url": url})
                result["tenant_params"].add(key.lower())

        path_match = TENANT_PATH_PATTERN.search(parsed.path)
        if path_match:
            result["path_params"].append(
                {
                    "parameter": "path_segment",
                    "value": path_match.group(1),
                    "url": url,
                    "pattern": path_match.group(0),
                }
            )
            result["tenant_params"].add("path_tenant")

    for response in responses:
        resp_url = str(response.get("url", ""))
        headers = response.get("headers", {}) or {}
        for header_name, header_value in headers.items():
            if header_name.lower() in TENANT_HEADER_NAMES:
                result["headers"].append(
                    {
                        "parameter": header_name,
                        "value": str(header_value),
                        "url": resp_url,
                    }
                )
                result["tenant_params"].add(header_name.lower())

        body = str(response.get("body_text", "") or response.get("body", "") or "")
        if body:
            for indicator in MULTI_TENANT_INDICATORS:
                if indicator in body.lower():
                    result["multi_tenant_detected"] = True
                    break

            json_data = _extract_json(body)
            if json_data:
                tenant_fields = _extract_tenant_from_json(json_data)
                for field in tenant_fields:
                    field["url"] = resp_url
                    result["json_fields"].append(field)
                    result["tenant_params"].add(field["parameter"].lower())

        body_lower = body.lower()
        for indicator in MULTI_TENANT_INDICATORS:
            if indicator in body_lower:
                result["multi_tenant_detected"] = True
                break

    result["tenant_params"] = sorted(result["tenant_params"])
    return result

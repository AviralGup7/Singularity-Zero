"""Endpoint resource grouping and bulk detection."""

from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.json.support import PAGINATION_PARAM_NAMES, resource_group_for_url


def endpoint_resource_groups(urls: set[str], limit: int = 40) -> list[dict[str, Any]]:
    """Group URLs by resource type."""
    groups: dict[str, dict[str, Any]] = {}
    for url in sorted(urls):
        resource = resource_group_for_url(url)
        if not resource:
            continue
        entry = groups.setdefault(
            resource, {"resource": resource, "endpoint_count": 0, "endpoints": []}
        )
        entry["endpoint_count"] += 1
        if len(entry["endpoints"]) < 8:
            entry["endpoints"].append(url)
    results = list(groups.values())
    results.sort(key=lambda item: (-item["endpoint_count"], item["resource"]))
    return results[:limit]


def bulk_endpoint_detector(urls: set[str], limit: int = 80) -> list[dict[str, Any]]:
    """Detect bulk/collection-style endpoints."""
    findings: list[dict[str, Any]] = []
    for url in sorted(urls):
        parsed = urlparse(url)
        path = parsed.path.lower()
        signals = []
        if any(token in path for token in ("/list", "/search", "/export", "/bulk", "/query")):
            signals.append("bulk_path_keyword")
        if path.endswith("s") and len(path.rsplit("/", 1)[-1]) > 2:
            signals.append("plural_collection_path")
        query_keys = {key for key, _ in meaningful_query_pairs(url)}
        if query_keys & {"q", "query", "search", "filter"}:
            signals.append("search_like_query")
        if query_keys & PAGINATION_PARAM_NAMES:
            signals.append("paged_collection")
        if not signals:
            continue
        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "resource_group": resource_group_for_url(url),
                "signals": sorted(set(signals)),
            }
        )
    findings.sort(key=lambda item: (-len(item["signals"]), item["url"]))
    return findings[:limit]

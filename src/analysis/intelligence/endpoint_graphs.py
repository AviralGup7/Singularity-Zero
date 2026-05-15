"""Relationship and finding graph builders for endpoint intelligence.

Contains functions for building endpoint relationship graphs, shared parameter
tracking, auth context mapping, and finding graphs.
Extracted from endpoint_intelligence.py for better separation of concerns.
"""

from itertools import combinations
from typing import Any
from urllib.parse import urlparse


def build_endpoint_relationship_graph(
    endpoint_intelligence: list[dict[str, Any]], limit: int = 24
) -> list[dict[str, Any]]:
    """Build a graph of relationships between endpoints based on shared attributes."""
    edges: list[dict[str, Any]] = []
    for left, right in combinations(endpoint_intelligence, 2):
        left_host = str(left.get("host", "")).strip().lower()
        right_host = str(right.get("host", "")).strip().lower()
        if left_host != right_host:
            continue
        shared_parameters = sorted(
            set(left.get("query_parameters", [])) & set(right.get("query_parameters", []))
        )
        shared_flow_labels = sorted(
            set(left.get("flow_labels", [])) & set(right.get("flow_labels", []))
        )
        shared_auth_contexts = sorted(
            set(left.get("auth_contexts", [])) & set(right.get("auth_contexts", []))
        )
        relationship_types: list[str] = []
        if left.get("resource_group") and left.get("resource_group") == right.get("resource_group"):
            relationship_types.append("shared_resource_group")
        if shared_parameters:
            relationship_types.append("shared_parameters")
        if shared_flow_labels:
            relationship_types.append("shared_flow")
        if shared_auth_contexts:
            relationship_types.append("shared_auth_context")
        if left.get("endpoint_type") == right.get("endpoint_type"):
            relationship_types.append("same_endpoint_type")
        if not relationship_types:
            continue
        score = (
            len(shared_parameters) * 2
            + len(shared_flow_labels) * 3
            + len(shared_auth_contexts) * 2
            + (3 if "shared_resource_group" in relationship_types else 0)
            + (1 if "same_endpoint_type" in relationship_types else 0)
        )
        edges.append(
            {
                "source_url": left.get("url", ""),
                "target_url": right.get("url", ""),
                "host": left_host,
                "relationship_types": relationship_types,
                "shared_parameters": shared_parameters[:8],
                "shared_flow_labels": shared_flow_labels[:6],
                "shared_auth_contexts": shared_auth_contexts[:6],
                "shared_resource_group": left.get("resource_group", "")
                if left.get("resource_group") == right.get("resource_group")
                else "",
                "score": score,
            }
        )
    edges.sort(key=lambda item: (-item["score"], item["source_url"], item["target_url"]))
    return edges[:limit]


def build_shared_parameter_tracking(
    endpoint_intelligence: list[dict[str, Any]], limit: int = 18
) -> list[dict[str, Any]]:
    """Track parameters shared across multiple endpoints."""
    parameter_map: dict[str, dict[str, Any]] = {}
    for item in endpoint_intelligence:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        for parameter in item.get("query_parameters", []):
            entry = parameter_map.setdefault(
                str(parameter),
                {
                    "parameter": str(parameter),
                    "urls": set(),
                    "hosts": set(),
                    "endpoint_types": set(),
                    "auth_contexts": set(),
                    "resource_groups": set(),
                },
            )
            entry["urls"].add(url)
            entry["hosts"].add(str(item.get("host", "")).strip().lower())
            entry["endpoint_types"].add(str(item.get("endpoint_type", "")).strip())
            entry["auth_contexts"].update(item.get("auth_contexts", []))
            if item.get("resource_group"):
                entry["resource_groups"].add(str(item.get("resource_group", "")).strip())
    findings = []
    for entry in parameter_map.values():
        if len(entry["urls"]) < 2:
            continue
        findings.append(
            {
                "parameter": entry["parameter"],
                "endpoint_count": len(entry["urls"]),
                "hosts": sorted(value for value in entry["hosts"] if value),
                "endpoint_types": sorted(value for value in entry["endpoint_types"] if value),
                "auth_contexts": sorted(value for value in entry["auth_contexts"] if value),
                "resource_groups": sorted(entry["resource_groups"])[:6],
                "urls": sorted(entry["urls"])[:8],
            }
        )
    findings.sort(key=lambda item: (-item["endpoint_count"], item["parameter"]))
    return findings[:limit]


def build_auth_context_mapping(
    endpoint_intelligence: list[dict[str, Any]], limit: int = 12
) -> list[dict[str, Any]]:
    """Map authentication contexts to their associated endpoints and signals."""
    context_map: dict[str, dict[str, Any]] = {}
    for item in endpoint_intelligence:
        contexts = set(item.get("auth_contexts", []))
        if len(contexts) >= 2:
            contexts.add("mixed")
        for context in contexts:
            entry = context_map.setdefault(
                str(context),
                {
                    "context": str(context),
                    "urls": set(),
                    "hosts": set(),
                    "signals": set(),
                    "resource_groups": set(),
                },
            )
            entry["urls"].add(str(item.get("url", "")).strip())
            entry["hosts"].add(str(item.get("host", "")).strip().lower())
            entry["signals"].update(item.get("signals", []))
            if item.get("resource_group"):
                entry["resource_groups"].add(str(item.get("resource_group", "")).strip())
    findings = []
    for entry in context_map.values():
        findings.append(
            {
                "context": entry["context"],
                "endpoint_count": len([url for url in entry["urls"] if url]),
                "hosts": sorted(value for value in entry["hosts"] if value),
                "top_signals": sorted(entry["signals"])[:8],
                "resource_groups": sorted(entry["resource_groups"])[:6],
                "urls": sorted(url for url in entry["urls"] if url)[:8],
            }
        )
    findings.sort(key=lambda item: (-item["endpoint_count"], item["context"]))
    return findings[:limit]


def build_finding_graph(
    endpoint_intelligence: list[dict[str, Any]],
    analysis_results: dict[str, list[dict[str, Any]]] | None = None,
    *,
    node_limit: int = 240,
    edge_limit: int = 360,
) -> dict[str, list[dict[str, Any]]]:
    """Build a finding graph connecting endpoints, parameters, roles, and tokens."""
    analysis_results = analysis_results or {}
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def ensure_node(node_type: str, key: str, label: str, **extra: object) -> str:
        node_id = f"{node_type}:{key}"
        existing = nodes.get(node_id)
        if existing:
            return node_id
        nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            **extra,
        }
        return node_id

    def connect(source: str, target: str, edge_type: str, **extra: object) -> None:
        edge_key = (source, target, edge_type)
        if edge_key in edges:
            existing = edges[edge_key]
            if "weight" in existing:
                existing["weight"] = int(existing.get("weight", 1)) + int(
                    str(extra.get("weight", 1))
                )
            return
        edges[edge_key] = {
            "source": source,
            "target": target,
            "type": edge_type,
            **extra,
        }

    endpoint_id_by_url: dict[str, str] = {}
    for item in endpoint_intelligence:
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        host = str(item.get("host", "") or urlparse(url).netloc.lower()).strip().lower()
        endpoint_id = ensure_node("endpoint", url, url, host=host)
        endpoint_id_by_url[url] = endpoint_id
        for parameter in item.get("query_parameters", []):
            value = str(parameter).strip().lower()
            if not value:
                continue
            parameter_id = ensure_node("parameter", value, value)
            connect(endpoint_id, parameter_id, "depends_on", weight=1)
        for role in item.get("auth_contexts", []):
            value = str(role).strip().lower()
            if not value:
                continue
            role_id = ensure_node("user_role", value, value)
            connect(endpoint_id, role_id, "depends_on", weight=1)

    for flow_item in analysis_results.get("flow_detector", []):
        chain = [str(url).strip() for url in flow_item.get("chain", []) if str(url).strip()]
        for left, right in zip(chain, chain[1:]):
            left_id = endpoint_id_by_url.get(left) or ensure_node(
                "endpoint", left, left, host=urlparse(left).netloc.lower()
            )
            right_id = endpoint_id_by_url.get(right) or ensure_node(
                "endpoint", right, right, host=urlparse(right).netloc.lower()
            )
            connect(left_id, right_id, "calls", label=str(flow_item.get("label", "flow")), weight=1)

    for token_item in analysis_results.get("token_leak_detector", []):
        url = str(token_item.get("url", "")).strip()
        if not url:
            continue
        endpoint_id = endpoint_id_by_url.get(url) or ensure_node(
            "endpoint", url, url, host=urlparse(url).netloc.lower()
        )
        token_key = str(token_item.get("endpoint_key") or url)
        location = str(token_item.get("location", "unknown")).strip().lower()
        token_id = ensure_node("token", f"{token_key}|{location}", f"token@{location}")
        connect(
            token_id, endpoint_id, "leaks_to", weight=max(1, int(token_item.get("leak_count", 1)))
        )

    for leak_item in analysis_results.get("referer_propagation_tracking", []):
        source = str(leak_item.get("url", "")).strip()
        target = str(leak_item.get("target_url", "")).strip()
        if not source or not target:
            continue
        source_id = endpoint_id_by_url.get(source) or ensure_node(
            "endpoint", source, source, host=urlparse(source).netloc.lower()
        )
        target_id = endpoint_id_by_url.get(target) or ensure_node(
            "endpoint", target, target, host=urlparse(target).netloc.lower()
        )
        connect(
            source_id,
            target_id,
            "leaks_to",
            parameter=str(leak_item.get("parameter", "")),
            weight=1,
        )

    node_list = sorted(nodes.values(), key=lambda item: (item["type"], item["label"]))[:node_limit]
    node_ids = {item["id"] for item in node_list}
    edge_list = [
        item
        for item in sorted(
            edges.values(),
            key=lambda edge: (
                -int(edge.get("weight", 1)),
                edge["type"],
                edge["source"],
                edge["target"],
            ),
        )
        if item["source"] in node_ids and item["target"] in node_ids
    ][:edge_limit]
    return {"nodes": node_list, "edges": edge_list}

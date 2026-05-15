"""Attack graph construction for endpoint intelligence.

Builds a directed graph of attack paths from endpoint intelligence data,
including node/edge creation, confidence propagation, and chain search.
Extracted from endpoint_intelligence.py for better separation of concerns.
"""

from dataclasses import dataclass
from itertools import combinations
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import endpoint_base_key, endpoint_signature, ensure_endpoint_key


@dataclass(frozen=True)
class AttackGraphNode:
    node_id: str
    endpoint_key: str
    endpoint_url: str
    identity: str
    resource: str
    host: str
    confidence: float


@dataclass(frozen=True)
class AttackGraphEdge:
    source: str
    target: str
    edge_type: str
    confidence: float
    evidence: dict[str, object]


def _identity_rank(identity: str) -> int:
    lowered = str(identity).strip().lower()
    order = {
        "public": 0,
        "unauthenticated": 0,
        "authenticated": 1,
        "auth_flow": 1,
        "restricted": 1,
        "privileged": 2,
        "admin": 2,
    }
    return order.get(lowered, 1)


def build_attack_graph(
    endpoint_intelligence: list[dict[str, Any]],
    analysis_results: dict[str, list[dict[str, Any]]] | None = None,
    *,
    node_limit: int = 220,
    edge_limit: int = 320,
    chain_limit: int = 14,
    max_chain_depth: int = 4,
) -> dict[str, object]:
    """Build an attack graph from endpoint intelligence data.

    Creates nodes for each endpoint+identity combination, edges for
    relationships (redirects, shared identifiers, state transitions, etc.),
    propagates confidence scores, and searches for attack chains.
    """
    analysis_results = analysis_results or {}
    endpoint_by_url = {
        str(item.get("url", "")).strip(): item
        for item in endpoint_intelligence
        if str(item.get("url", "")).strip()
    }
    nodes: dict[str, AttackGraphNode] = {}
    edges: dict[tuple[str, str, str], AttackGraphEdge] = {}
    endpoint_nodes: dict[str, set[str]] = {}

    def ensure_node(endpoint_item: dict[str, Any], identity: str) -> str:
        endpoint_key = ensure_endpoint_key(
            endpoint_item, str(endpoint_item.get("url", "")).strip()
        ).strip()
        url = str(endpoint_item.get("url", "")).strip()
        host = str(endpoint_item.get("host") or urlparse(url).netloc.lower()).strip().lower()
        resource = (
            str(
                endpoint_item.get("resource_group")
                or endpoint_item.get("endpoint_base_key")
                or endpoint_key
                or "unknown"
            )
            .strip()
            .lower()
        )
        identity_value = str(identity or "public").strip().lower() or "public"
        node_id = f"{endpoint_key}|{identity_value}|{resource}"
        if node_id not in nodes:
            nodes[node_id] = AttackGraphNode(
                node_id=node_id,
                endpoint_key=endpoint_key,
                endpoint_url=url,
                identity=identity_value,
                resource=resource,
                host=host,
                confidence=float(endpoint_item.get("evidence_confidence", 0.42) or 0.42),
            )
        endpoint_nodes.setdefault(endpoint_key, set()).add(node_id)
        return node_id

    def add_edge(
        source: str, target: str, edge_type: str, confidence: float, evidence: dict[str, Any]
    ) -> None:
        if source == target and edge_type != "state_transition":
            return
        key = (source, target, edge_type)
        bounded = round(max(0.05, min(float(confidence or 0.0), 0.99)), 3)
        existing = edges.get(key)
        if existing is None or bounded > existing.confidence:
            edges[key] = AttackGraphEdge(
                source=source,
                target=target,
                edge_type=edge_type,
                confidence=bounded,
                evidence=evidence,
            )

    # Auth context switch edges
    for item in endpoint_intelligence:
        contexts = [
            str(context).strip().lower()
            for context in item.get("auth_contexts", [])
            if str(context).strip()
        ]
        if not contexts:
            contexts = ["public"]
        for context in contexts:
            ensure_node(item, context)
        ordered_contexts = sorted(set(contexts), key=_identity_rank)
        for lower, higher in zip(ordered_contexts, ordered_contexts[1:]):
            source_node = ensure_node(item, lower)
            target_node = ensure_node(item, higher)
            add_edge(
                source_node,
                target_node,
                "auth_context_switch",
                0.58 + min(len(ordered_contexts), 4) * 0.06,
                {"endpoint": item.get("url", ""), "from": lower, "to": higher},
            )

    # Redirect edges
    redirect_modules = [
        *analysis_results.get("redirect_chain_analyzer", []),
        *analysis_results.get("auth_boundary_redirect_detection", []),
    ]
    for item in redirect_modules:
        source_url = str(item.get("url", "")).strip()
        target_url = str(item.get("final_url", "")).strip()
        if not source_url or not target_url or source_url == target_url:
            continue
        source_endpoint = endpoint_by_url.get(source_url)
        target_endpoint = endpoint_by_url.get(target_url)
        if not source_endpoint:
            continue
        source_contexts = source_endpoint.get("auth_contexts", ["authenticated"])
        target_contexts = (
            target_endpoint.get("auth_contexts", source_contexts)
            if target_endpoint
            else source_contexts
        )
        source_node = ensure_node(
            source_endpoint, str(source_contexts[0] if source_contexts else "authenticated")
        )
        target_node = ensure_node(
            target_endpoint
            or {
                "url": target_url,
                "endpoint_key": endpoint_signature(target_url),
                "endpoint_base_key": endpoint_base_key(target_url),
                "resource_group": "external",
                "host": urlparse(target_url).netloc.lower(),
                "evidence_confidence": 0.45,
            },
            str(target_contexts[0] if target_contexts else "authenticated"),
        )
        add_edge(
            source_node,
            target_node,
            "redirects_to",
            0.55 + (0.18 if bool(item.get("cross_host") or item.get("boundary_changed")) else 0.0),
            {"url": source_url, "final_url": target_url},
        )

    # Shared identifier edges
    identifier_names = {
        "id",
        "user_id",
        "account_id",
        "tenant_id",
        "order_id",
        "invoice_id",
        "member_id",
        "profile_id",
    }
    for left, right in combinations(endpoint_intelligence, 2):
        left_host = str(left.get("host", "")).strip().lower()
        right_host = str(right.get("host", "")).strip().lower()
        if not left_host or left_host != right_host:
            continue
        left_params = {
            str(value).strip().lower()
            for value in left.get("query_parameters", [])
            if str(value).strip()
        }
        right_params = {
            str(value).strip().lower()
            for value in right.get("query_parameters", [])
            if str(value).strip()
        }
        shared_identifier = sorted(
            value
            for value in (left_params & right_params)
            if value in identifier_names or value.endswith("_id")
        )
        if not shared_identifier:
            continue
        left_context = str((left.get("auth_contexts") or ["authenticated"])[0])
        right_context = str((right.get("auth_contexts") or ["authenticated"])[0])
        left_node = ensure_node(left, left_context)
        right_node = ensure_node(right, right_context)
        confidence = 0.46 + min(len(shared_identifier), 3) * 0.09
        if left.get("resource_group") and left.get("resource_group") == right.get("resource_group"):
            confidence += 0.08
        evidence: dict[str, object] = {
            "shared_identifiers": shared_identifier[:8],
            "host": left_host,
        }
        add_edge(left_node, right_node, "shares_identifier_with", confidence, evidence)
        add_edge(right_node, left_node, "shares_identifier_with", confidence, evidence)

    # Referer propagation edges
    for item in analysis_results.get("referer_propagation_tracking", []):
        source_url = str(item.get("url", "")).strip()
        if not source_url:
            continue
        source_endpoint = endpoint_by_url.get(source_url)
        if not source_endpoint:
            continue
        source_context = str((source_endpoint.get("auth_contexts") or ["authenticated"])[0])
        source_node = ensure_node(source_endpoint, source_context)
        for target_url in item.get("external_references", [])[:4]:
            target = str(target_url).strip()
            if not target:
                continue
            target_endpoint = endpoint_by_url.get(target)
            target_node = ensure_node(
                target_endpoint
                or {
                    "url": target,
                    "endpoint_key": endpoint_signature(target),
                    "endpoint_base_key": endpoint_base_key(target),
                    "resource_group": "external",
                    "host": urlparse(target).netloc.lower(),
                    "evidence_confidence": 0.4,
                },
                "external",
            )
            add_edge(
                source_node,
                target_node,
                "leaks_to",
                0.57 + (0.16 if bool(item.get("propagation_risk")) else 0.0),
                {
                    "source": source_url,
                    "target": target,
                    "sensitive_params": item.get("sensitive_params", [])[:4],
                },
            )

    # State transition edges
    for item in analysis_results.get("state_transition_analyzer", []):
        source_url = str(item.get("url", "")).strip()
        target_url = str(item.get("mutated_url", "")).strip()
        if not source_url or not target_url:
            continue
        source_endpoint = endpoint_by_url.get(source_url)
        if not source_endpoint:
            continue
        source_node = ensure_node(
            source_endpoint, str((source_endpoint.get("auth_contexts") or ["authenticated"])[0])
        )
        target_endpoint = endpoint_by_url.get(target_url) or source_endpoint
        target_node = ensure_node(
            target_endpoint, str((target_endpoint.get("auth_contexts") or ["authenticated"])[0])
        )
        add_edge(
            source_node,
            target_node,
            "state_transition",
            0.54 + (0.2 if bool(item.get("state_mismatch")) else 0.0),
            {
                "parameter": item.get("parameter", ""),
                "original_value": item.get("original_value", ""),
                "mutated_value": item.get("mutated_value", ""),
            },
        )

    propagated = _propagate_attack_confidence(nodes, edges)
    chains = _search_attack_chains(
        nodes, edges, propagated, limit=chain_limit, max_depth=max_chain_depth
    )

    node_list = sorted(
        (
            {
                "id": node.node_id,
                "endpoint_key": node.endpoint_key,
                "endpoint_url": node.endpoint_url,
                "identity": node.identity,
                "resource": node.resource,
                "host": node.host,
                "base_confidence": round(node.confidence, 3),
                "propagated_confidence": round(propagated.get(node.node_id, node.confidence), 3),
            }
            for node in nodes.values()
        ),
        key=lambda item: (
            -float(item["propagated_confidence"])
            if isinstance(item["propagated_confidence"], (int, float))
            else 0.0,
            item["id"],
        ),
    )[:node_limit]
    node_ids = {item["id"] for item in node_list}

    edge_list = sorted(
        (
            {
                "source": edge.source,
                "target": edge.target,
                "type": edge.edge_type,
                "confidence": edge.confidence,
                "propagated_confidence": round(
                    min(
                        propagated.get(edge.source, 0.0),
                        propagated.get(edge.target, 0.0),
                    )
                    * edge.confidence,
                    3,
                ),
                "evidence": edge.evidence,
            }
            for edge in edges.values()
            if edge.source in node_ids and edge.target in node_ids
        ),
        key=lambda item: (
            -float(item["propagated_confidence"])
            if isinstance(item["propagated_confidence"], (int, float))
            else 0.0,
            -float(item["confidence"]) if isinstance(item["confidence"], (int, float)) else 0.0,
            item["type"],
        ),
    )[:edge_limit]

    return {
        "nodes": node_list,
        "edges": edge_list,
        "chains": chains,
        "endpoint_nodes": {key: sorted(values) for key, values in endpoint_nodes.items()},
    }


def _propagate_attack_confidence(
    nodes: dict[str, AttackGraphNode],
    edges: dict[tuple[str, str, str], AttackGraphEdge],
    *,
    attenuation: float = 0.95,
) -> dict[str, float]:
    """Propagate confidence scores across the attack graph edges."""
    propagated = {node_id: max(0.05, min(node.confidence, 0.99)) for node_id, node in nodes.items()}
    for _ in range(4):
        changed = False
        for edge in edges.values():
            source_confidence = propagated.get(edge.source, 0.0)
            candidate = source_confidence * edge.confidence * attenuation
            if candidate > propagated.get(edge.target, 0.0):
                propagated[edge.target] = round(min(candidate, 0.99), 4)
                changed = True
        if not changed:
            break
    return propagated


def _search_attack_chains(
    nodes: dict[str, AttackGraphNode],
    edges: dict[tuple[str, str, str], AttackGraphEdge],
    propagated: dict[str, float],
    *,
    limit: int,
    max_depth: int,
) -> list[dict[str, Any]]:
    """Search for high-confidence attack chains through the graph."""
    adjacency: dict[str, list[AttackGraphEdge]] = {}
    for edge in edges.values():
        adjacency.setdefault(edge.source, []).append(edge)

    chains: list[dict[str, Any]] = []

    def walk(current: str, path_nodes: list[str], path_edges: list[AttackGraphEdge]) -> None:
        if len(path_edges) >= 2:
            node_confidences = [propagated.get(node_id, 0.0) for node_id in path_nodes]
            edge_confidences = [edge.confidence for edge in path_edges]
            chain_confidence = round(
                min(node_confidences + edge_confidences)
                if node_confidences and edge_confidences
                else 0.0,
                3,
            )
            endpoint_keys = []
            for node_id in path_nodes:
                key = nodes[node_id].endpoint_key
                if key not in endpoint_keys:
                    endpoint_keys.append(key)
            edge_types = [edge.edge_type for edge in path_edges]
            chains.append(
                {
                    "node_ids": path_nodes[:],
                    "endpoint_keys": endpoint_keys,
                    "edge_types": edge_types,
                    "steps": [
                        {
                            "from": edge.source,
                            "to": edge.target,
                            "type": edge.edge_type,
                            "confidence": edge.confidence,
                        }
                        for edge in path_edges
                    ],
                    "confidence": chain_confidence,
                }
            )
        if len(path_edges) >= max_depth:
            return
        for edge in adjacency.get(current, []):
            if edge.target in path_nodes:
                continue
            walk(edge.target, [*path_nodes, edge.target], [*path_edges, edge])

    starters = sorted(
        nodes.values(),
        key=lambda node: (
            node.identity not in {"public", "authenticated", "auth_flow"},
            -propagated.get(node.node_id, 0.0),
        ),
    )
    for node in starters[:24]:
        walk(node.node_id, [node.node_id], [])

    unique: dict[tuple[str, ...], dict[str, Any]] = {}
    for chain in chains:
        key = tuple(chain["node_ids"])
        existing = unique.get(key)
        if existing is None or float(chain.get("confidence", 0.0)) > float(
            existing.get("confidence", 0.0)
        ):
            unique[key] = chain

    ranked = sorted(
        unique.values(),
        key=lambda chain: (
            -float(chain.get("confidence", 0.0)),
            -len(chain.get("steps", [])),
            "->".join(chain.get("edge_types", [])),
        ),
    )
    return ranked[:limit]

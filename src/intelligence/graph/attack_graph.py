"""Algorithmic Multi-Hop Attack Path & Exploit Chain Engine.

Constructs directed threat graphs connecting discovery assets, vulnerability findings,
and exposed credentials to identify exploitable multi-hop lateral movement chains.
"""

from __future__ import annotations

import collections
import heapq
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GraphNode:
    """Represents an asset, vulnerability, credential, or impact target in the attack graph."""

    id: str
    node_type: str  # "asset", "finding", "credential", "impact"
    label: str
    severity: str = "info"  # "info", "low", "medium", "high", "critical"
    metadata: tuple[tuple[str, Any], ...] = ()

    @property
    def severity_weight(self) -> float:
        weights = {"info": 1.0, "low": 2.0, "medium": 4.0, "high": 7.0, "critical": 10.0}
        return weights.get(self.severity.lower(), 1.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type,
            "label": self.label,
            "severity": self.severity,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """Represents a lateral transition or exploit dependency between nodes."""

    source_id: str
    target_id: str
    relation: str  # "EXPOSES", "AUTHENTICATES", "LEADS_TO", "ESCALATES_TO"
    weight: float = 1.0  # Cost/difficulty (lower means easier path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "weight": self.weight,
        }


@dataclass(frozen=True, slots=True)
class AttackChain:
    """Multi-hop attack path from initial discovery to high-impact exploitation."""

    chain_id: str
    entry_point_id: str
    target_id: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    total_risk: float
    hop_count: int
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "entry_point_id": self.entry_point_id,
            "target_id": self.target_id,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "total_risk": self.total_risk,
            "hop_count": self.hop_count,
            "summary": self.summary,
        }


class AttackGraphEngine:
    """In-memory multi-hop graph traversal, reachability, and exploit chain synthesizer."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, list[GraphEdge]] = collections.defaultdict(list)
        self._reverse_edges: dict[str, list[GraphEdge]] = collections.defaultdict(list)

    def add_node(self, node: GraphNode) -> None:
        self._nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self._edges[edge.source_id].append(edge)
        self._reverse_edges[edge.target_id].append(edge)

    def build_from_findings(self, findings: list[dict[str, Any]], endpoints: list[dict[str, Any]] | None = None) -> None:
        """Construct graph nodes and lateral edges from standard pipeline findings."""
        # 1. Add endpoint assets
        for ep in endpoints or []:
            url = ep.get("url") or ep.get("host", "")
            if not url:
                continue
            node_id = f"asset:{url}"
            self.add_node(
                GraphNode(
                    id=node_id,
                    node_type="asset",
                    label=url,
                    severity="info",
                )
            )

        # 2. Add findings and create edges
        for f in findings:
            fid = str(f.get("id") or f.get("finding_id") or uuid.uuid4().hex[:8])
            node_id = f"finding:{fid}"
            f_url = f.get("url", "")
            cat = str(f.get("category", "vulnerability")).lower()
            sev = str(f.get("severity", "medium")).lower()

            self.add_node(
                GraphNode(
                    id=node_id,
                    node_type="finding",
                    label=f.get("title", cat),
                    severity=sev,
                    metadata=tuple((k, str(v)) for k, v in f.items() if k not in ("title", "severity")),
                )
            )

            # Link asset -> finding
            if f_url:
                asset_id = f"asset:{f_url}"
                if asset_id not in self._nodes:
                    self.add_node(GraphNode(id=asset_id, node_type="asset", label=f_url, severity="info"))
                self.add_edge(GraphEdge(source_id=asset_id, target_id=node_id, relation="EXPOSES", weight=1.0))

            # Infer credential / impact relations
            if any(k in cat for k in ("sqli", "rce", "command_injection", "deserialization")):
                impact_id = f"impact:takeover:{fid}"
                self.add_node(GraphNode(id=impact_id, node_type="impact", label=f"Host Compromise ({cat})", severity="critical"))
                self.add_edge(GraphEdge(source_id=node_id, target_id=impact_id, relation="ESCALATES_TO", weight=0.5))

            elif any(k in cat for k in ("jwt", "auth", "idor", "bac", "credential")):
                impact_id = f"impact:privilege_escalation:{fid}"
                self.add_node(GraphNode(id=impact_id, node_type="impact", label=f"Privilege Escalation ({cat})", severity="high"))
                self.add_edge(GraphEdge(source_id=node_id, target_id=impact_id, relation="AUTHENTICATES", weight=1.0))

    def find_shortest_attack_paths(
        self,
        entry_node_id: str,
        max_hops: int = 6,
    ) -> list[AttackChain]:
        """Compute shortest exploit chains from an entry point using Dijkstra's algorithm."""
        if entry_node_id not in self._nodes:
            return []

        distances: dict[str, float] = {entry_node_id: 0.0}
        predecessors: dict[str, tuple[str, GraphEdge]] = {}
        pq: list[tuple[float, str, int]] = [(0.0, entry_node_id, 0)]

        while pq:
            cost, current, hops = heapq.heappop(pq)

            if hops >= max_hops:
                continue
            if cost > distances.get(current, float("inf")):
                continue

            for edge in self._edges.get(current, []):
                new_cost = cost + edge.weight
                neighbor = edge.target_id
                if new_cost < distances.get(neighbor, float("inf")):
                    distances[neighbor] = new_cost
                    predecessors[neighbor] = (current, edge)
                    heapq.heappush(pq, (new_cost, neighbor, hops + 1))

        # Reconstruct chains to all reached impact nodes
        chains: list[AttackChain] = []
        for target_id, target_node in self._nodes.items():
            if target_node.node_type != "impact" or target_id not in distances:
                continue

            # Trace path back to entry_node_id
            curr = target_id
            path_nodes = [self._nodes[curr]]
            path_edges: list[GraphEdge] = []

            while curr != entry_node_id:
                if curr not in predecessors:
                    break
                prev, edge = predecessors[curr]
                path_nodes.append(self._nodes[prev])
                path_edges.append(edge)
                curr = prev

            path_nodes.reverse()
            path_edges.reverse()

            total_risk = sum(n.severity_weight for n in path_nodes)
            summary = f"Chain: {' -> '.join(n.label for n in path_nodes)}"
            chains.append(
                AttackChain(
                    chain_id=f"chain_{uuid.uuid4().hex[:8]}",
                    entry_point_id=entry_node_id,
                    target_id=target_id,
                    nodes=tuple(path_nodes),
                    edges=tuple(path_edges),
                    total_risk=total_risk,
                    hop_count=len(path_edges),
                    summary=summary,
                )
            )

        chains.sort(key=lambda c: c.total_risk, reverse=True)
        return chains

    def export_graph(self) -> dict[str, Any]:
        """Export full graph structure and synthesized chains."""
        all_chains: list[AttackChain] = []
        for node_id, node in self._nodes.items():
            if node.node_type == "asset":
                all_chains.extend(self.find_shortest_attack_paths(node_id))

        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for edge_list in self._edges.values() for e in edge_list],
            "chains": [c.to_dict() for c in all_chains],
            "total_nodes": len(self._nodes),
            "total_edges": sum(len(e) for e in self._edges.values()),
        }


__all__ = [
    "AttackChain",
    "AttackGraphEngine",
    "GraphEdge",
    "GraphNode",
]

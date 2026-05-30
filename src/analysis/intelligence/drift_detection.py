"""Safe/defensive Jaccard similarity engine for exploit chain drift detection across multi-hop runs.

Compares nodes, edges, and chain structures between historical and current attack graphs.
"""

from __future__ import annotations

from typing import Any


class ExploitChainDriftEngine:
    """Calculates structural drift of attack paths between different assessment runs."""

    @staticmethod
    def extract_graph_features(attack_graph: dict[str, Any]) -> set[str]:
        """Convert attack graph nodes, edges, and chains into a standardized set of feature strings.

        Args:
            attack_graph: The attack graph dictionary containing "nodes", "edges", and "chains".

        Returns:
            A set of unique string representation signatures for graph components.
        """
        features: set[str] = set()

        # 1. Add node features
        for node in attack_graph.get("nodes", []):
            node_id = node.get("id")
            if node_id:
                features.add(f"node:{node_id}")

        # 2. Add edge features
        for edge in attack_graph.get("edges", []):
            source = edge.get("source")
            target = edge.get("target")
            edge_type = edge.get("type")
            if source and target and edge_type:
                features.add(f"edge:{source}->{edge_type}->{target}")

        # 3. Add chain features
        for chain in attack_graph.get("chains", []):
            node_ids = chain.get("node_ids", [])
            edge_types = chain.get("edge_types", [])
            if node_ids and len(node_ids) >= 2:
                sig = f"chain:{node_ids[0]}->{'-'.join(edge_types)}->{node_ids[-1]}"
                features.add(sig)

        return features

    @classmethod
    def calculate_jaccard_similarity(
        cls, graph_a: dict[str, Any], graph_b: dict[str, Any]
    ) -> float:
        """Calculate Jaccard similarity coefficient between two attack graphs.

        Args:
            graph_a: First attack graph.
            graph_b: Second attack graph.

        Returns:
            Jaccard similarity coefficient as a float between 0.0 and 1.0.
        """
        features_a = cls.extract_graph_features(graph_a)
        features_b = cls.extract_graph_features(graph_b)

        if not features_a and not features_b:
            return 1.0  # Both graphs are empty, so they are identical

        intersection = features_a & features_b
        union = features_a | features_b

        return len(intersection) / len(union)

    @classmethod
    def detect_drift(
        cls, graph_a: dict[str, Any], graph_b: dict[str, Any], threshold: float = 0.8
    ) -> dict[str, Any]:
        """Detect drift between two attack graphs and determine if structural changes exceed threshold.

        Args:
            graph_a: Reference historical attack graph.
            graph_b: Current run attack graph.
            threshold: Jaccard similarity threshold under which a drift is declared (default 0.8).

        Returns:
            Dictionary with drift metrics and diff summaries.
        """
        similarity = cls.calculate_jaccard_similarity(graph_a, graph_b)
        has_drifted = similarity < threshold

        features_a = cls.extract_graph_features(graph_a)
        features_b = cls.extract_graph_features(graph_b)

        added = sorted(list(features_b - features_a))
        removed = sorted(list(features_a - features_b))

        return {
            "similarity": round(similarity, 4),
            "threshold": threshold,
            "has_drifted": has_drifted,
            "added_features_count": len(added),
            "removed_features_count": len(removed),
            "added_features": added,
            "removed_features": removed,
        }

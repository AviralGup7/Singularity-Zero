"""Threat graph construction and analysis.

Provides graph-based analysis of findings, endpoints, and attack paths.
Re-exports from analysis.intelligence for backward compatibility while
adding intelligence-layer-specific graph operations.
"""

from src.analysis.intelligence.endpoint_attack_graph import (
    AttackGraphEdge,
    AttackGraphNode,
    build_attack_graph,
)
from src.analysis.intelligence.endpoint_graphs import (
    build_finding_graph,
)
from src.intelligence.graph.threat_graph import (
    build_threat_graph,
    find_critical_paths,
    graph_risk_summary,
)

__all__ = [
    # Re-exports from analysis
    "build_attack_graph",
    "build_finding_graph",
    "AttackGraphNode",
    "AttackGraphEdge",
    # Intelligence-layer additions
    "build_threat_graph",
    "find_critical_paths",
    "graph_risk_summary",
]

"""
Cyber Security Test Pipeline - DAG-Based Execution Engine
Implements dependency-aware stage orchestration for maximum parallelism.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class PipelineDAG:
    """Manages the dependency graph of pipeline stages."""

    def __init__(self):
        self._graph = nx.DiGraph()
        self._stage_methods = {}

    def add_stage(self, name: str, method: Any, dependencies: list[str] | None = None):
        """Register a stage and its requirements."""
        self._graph.add_node(name)
        self._stage_methods[name] = method
        if dependencies:
            for dep in dependencies:
                self._graph.add_edge(dep, name)

    def get_execution_order(self) -> list[list[str]]:
        """
        Compute the optimal parallel execution plan using topological layers.
        Returns a list of 'tiers', where each tier can be executed concurrently.
        """
        if not nx.is_directed_acyclic_graph(self._graph):
            cycles = list(nx.simple_cycles(self._graph))
            raise ValueError(f"Circular dependencies detected in pipeline graph: {cycles}")

        # Compute tiers (generations) for maximum concurrency
        tiers = []
        temp_graph = self._graph.copy()
        while temp_graph:
            # Nodes with zero in-degree are ready for this tier
            ready = [node for node, degree in temp_graph.in_degree() if degree == 0]
            if not ready:
                break
            tiers.append(ready)
            temp_graph.remove_nodes_from(ready)

        return tiers

    def get_method(self, stage_name: str) -> Any:
        return self._stage_methods.get(stage_name)

    def visualize(self):
        """Log the computed execution flow."""
        tiers = self.get_execution_order()
        for i, tier in enumerate(tiers):
            logger.info("DAG Tier %d [Parallel]: %s", i, ", ".join(tier))

def build_neural_mesh_dag(stage_methods: dict[str, Any]) -> PipelineDAG:
    """Constructs the frontier 'Neural-Mesh' dependency graph."""
    dag = PipelineDAG()

    # Tier 0: Startup & Discovery (Independent)
    dag.add_stage("startup", stage_methods.get("startup"))
    dag.add_stage("subdomains", stage_methods.get("subdomains"), ["startup"])

    # Tier 1: Asset Mining
    dag.add_stage("live_hosts", stage_methods.get("live_hosts"), ["subdomains"])

    # Tier 2: Heavy Collection (Depends on live assets)
    dag.add_stage("urls", stage_methods.get("urls"), ["live_hosts"])

    # Tier 3: Passive Analysis (Starts immediately on URL discovery)
    dag.add_stage("parameters", stage_methods.get("parameters"), ["urls"])
    dag.add_stage("ranking", stage_methods.get("ranking"), ["urls"])

    # Tier 4: Parallel Deep Scan Group
    dag.add_stage("passive_scan", stage_methods.get("passive_scan"), ["parameters", "ranking"])
    dag.add_stage("nuclei", stage_methods.get("nuclei"), ["live_hosts"])
    dag.add_stage("semgrep", stage_methods.get("semgrep"), ["urls"])

    # Tier 5: Intelligent Decision & Validation
    dag.add_stage("active_scan", stage_methods.get("active_scan"), ["passive_scan"])
    dag.add_stage("intelligence", stage_methods.get("intelligence"), ["passive_scan", "nuclei", "semgrep"])

    # Tier 6: Final Reporting
    dag.add_stage("reporting", stage_methods.get("reporting"), ["intelligence", "active_scan"])

    return dag

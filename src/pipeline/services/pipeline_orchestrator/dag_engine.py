"""
Cyber Security Test Pipeline - DAG-Based Execution Engine
Implements dependency-aware stage orchestration for maximum parallelism.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

try:
    import networkx as nx
except ModuleNotFoundError:
    nx = None

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


class PipelineDAG:
    """Manages the dependency graph of pipeline stages."""

    def __init__(self) -> None:
        self._graph = nx.DiGraph() if nx is not None else _SimpleDiGraph()
        self._stage_methods: dict[str, Any] = {}

    def add_stage(self, name: str, method: Any, dependencies: list[str] | None = None) -> None:
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
        if nx is not None and not nx.is_directed_acyclic_graph(self._graph):
            cycles = list(nx.simple_cycles(self._graph))
            raise ValueError(f"Circular dependencies detected in pipeline graph: {cycles}")
        if nx is None and self._graph.has_cycle():
            raise ValueError("Circular dependencies detected in pipeline graph")

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

    def visualize(self) -> None:
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


class _SimpleDiGraph:
    """Small dependency graph fallback used when networkx is unavailable."""

    def __init__(self) -> None:
        self._nodes: set[str] = set()
        self._edges: dict[str, set[str]] = defaultdict(set)

    def add_node(self, name: str) -> None:
        self._nodes.add(name)

    def add_edge(self, source: str, target: str) -> None:
        self._nodes.update({source, target})
        self._edges[source].add(target)

    def copy(self) -> _SimpleDiGraph:
        clone = _SimpleDiGraph()
        clone._nodes = set(self._nodes)
        clone._edges = defaultdict(set, {key: set(value) for key, value in self._edges.items()})
        return clone

    def __bool__(self) -> bool:
        return bool(self._nodes)

    def in_degree(self) -> list[tuple[str, int]]:
        incoming = {node: 0 for node in self._nodes}
        for targets in self._edges.values():
            for target in targets:
                incoming[target] = incoming.get(target, 0) + 1
        return list(incoming.items())

    def remove_nodes_from(self, nodes: list[str]) -> None:
        remove = set(nodes)
        self._nodes.difference_update(remove)
        for node in remove:
            self._edges.pop(node, None)
        for targets in self._edges.values():
            targets.difference_update(remove)

    def has_cycle(self) -> bool:
        incoming = {node: 0 for node in self._nodes}
        for targets in self._edges.values():
            for target in targets:
                incoming[target] = incoming.get(target, 0) + 1
        queue = deque(node for node, degree in incoming.items() if degree == 0)
        visited = 0
        while queue:
            node = queue.popleft()
            visited += 1
            for target in self._edges.get(node, set()):
                incoming[target] -= 1
                if incoming[target] == 0:
                    queue.append(target)
        return visited != len(incoming)

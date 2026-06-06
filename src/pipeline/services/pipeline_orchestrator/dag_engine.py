"""
Cyber Security Test Pipeline - DAG-Based Execution Engine
Imports the canonical declarative graph from ``_graph_dsl`` via ``_constants``
and exposes backward-compatible wrappers for any call site that still
instantiates :class:`PipelineDAG` directly (the ``NeuralMesh`` tier code in
``dag_engine`` is purely a shim — the active scheduler in
``actor_scheduler.ActorScheduler`` operates on the ``Graph`` object directly
and does not call ``get_execution_order``).
"""

from __future__ import annotations

from typing import Any

from ._constants import STAGE_GRAPH


class _SimpleDiGraph:
    """Small dependency graph fallback retained for imports only."""

    def __init__(self) -> None:
        self._nodes: set[str] = set()
        self._edges: dict[str, set[str]] = {}

    def add_node(self, name: str) -> None:
        self._nodes.add(name)

    def add_edge(self, source: str, target: str) -> None:
        self._nodes.update({source, target})
        self._edges.setdefault(source, set()).add(target)

    def copy(self) -> _SimpleDiGraph:
        clone = _SimpleDiGraph()
        clone._nodes = set(self._nodes)
        clone._edges = {key: set(value) for key, value in self._edges.items()}
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
        edges_to_update = list(self._edges.items())
        for _node_key, targets in edges_to_update:
            targets.difference_update(remove)

    def has_cycle(self) -> bool:
        incoming = {node: 0 for node in self._nodes}
        for targets in self._edges.values():
            for target in targets:
                incoming[target] = incoming.get(target, 0) + 1
        from collections import deque

        queue: deque[str] = deque(node for node, degree in incoming.items() if degree == 0)
        visited = 0
        while queue:
            node = queue.popleft()
            visited += 1
            for target in self._edges.get(node, set()):
                incoming[target] -= 1
                if incoming[target] == 0:
                    queue.append(target)
        return visited != len(incoming)


class PipelineDAG:
    """Backward-compatible shim over the new declarative ``Graph`` DSL.

    Legacy callers that call ``add_stage`` or ``get_execution_order``
    still work; new code should import ``Graph`` and ``build_pipeline_graph``
    directly.
    """

    def __init__(self) -> None:
        self._graph = STAGE_GRAPH
        self._stage_methods: dict[str, Any] = {}

    def add_stage(self, name: str, method: Any, dependencies: list[str] | None = None) -> None:
        self._stage_methods[name] = method

    def get_execution_order(self) -> list[list[str]]:
        ready: list[list[str]] = []
        completed: set[str] = set()
        remaining = set(self._graph.names())
        while remaining:
            tier = [
                node.name
                for node in self._graph.nodes
                if node.name in remaining
                and all(dep in completed for dep in node.needs)
            ]
            if not tier:
                break
            ready.append(tier)
            completed.update(tier)
            remaining.difference_update(tier)
        return ready

    def get_method(self, stage_name: str) -> Any:
        return self._stage_methods.get(stage_name)

    def visualize(self) -> None:
        import logging

        tiers = self.get_execution_order()
        for i, tier in enumerate(tiers):
            logging.getLogger(__name__).info("DAG Tier %d [Parallel]: %s", i, ", ".join(tier))


def build_neural_mesh_dag(stage_methods: dict[str, Any]) -> PipelineDAG:
    """Return a :class:`PipelineDAG` shim mirroring the active ``STAGE_GRAPH``.

    The returned object uses the current ``STAGE_GRAPH`` (from ``_constants``)
    as its canonical source of truth; tier computation, condition gating, and
    priority weighting all come from the ``StageNode`` definitions, not from the
    now-obsolete ``STAGE_DEPS`` mapping.
    """
    dag = PipelineDAG()
    dag._stage_methods = dict(stage_methods)
    return dag


__all__ = ["PipelineDAG", "build_neural_mesh_dag", "_SimpleDiGraph"]

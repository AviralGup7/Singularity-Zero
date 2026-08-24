"""Symbolic Attack Graph (DAG) Reachability Solver.

Models complex multi-step vulnerability validation as a formal directed acyclic
graph of pre/post-conditions, performing topological reachability analysis and
pruning impossible attack vectors before probe execution.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class AttackNode:
    """Single vertex in the attack graph representing an exploit / validation step."""

    node_id: str
    action: str
    required_facts: tuple[str, ...] = ()
    emitted_facts: tuple[str, ...] = ()
    score_weight: int = 10
    goal: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "action": self.action,
            "required_facts": list(self.required_facts),
            "emitted_facts": list(self.emitted_facts),
            "score_weight": self.score_weight,
            "goal": self.goal,
        }


@dataclass(frozen=True, slots=True)
class AttackEdge:
    """Directed transition dependency between attack steps."""

    source_id: str
    target_id: str
    guard_condition: str = ""


class AttackDAG:
    """Directed Acyclic Attack Graph representing a compound validation strategy."""

    def __init__(self, dag_id: str, title: str = "") -> None:
        self.dag_id = dag_id
        self.title = title
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []

    def add_node(self, node: AttackNode) -> None:
        self.nodes[node.node_id] = node

    def add_edge(self, source_id: str, target_id: str, guard: str = "") -> None:
        if source_id not in self.nodes or target_id not in self.nodes:
            raise ValueError(f"Edge nodes {source_id} -> {target_id} must exist in DAG")
        self.edges.append(AttackEdge(source_id=source_id, target_id=target_id, guard_condition=guard))

    def solve_reachability(self, known_facts: set[str]) -> list[AttackNode]:
        """Evaluate topological reachability given the set of observed endpoint facts.

        Returns an ordered, pruned sequence of executable attack nodes.
        """
        available_facts = set(known_facts)
        in_degrees: dict[str, int] = {nid: 0 for nid in self.nodes}
        adj: dict[str, list[str]] = {nid: [] for nid in self.nodes}

        for edge in self.edges:
            adj[edge.source_id].append(edge.target_id)
            in_degrees[edge.target_id] += 1

        # Queue nodes with 0 incoming dependencies whose preconditions are met
        queue: deque[str] = deque(
            nid
            for nid, deg in in_degrees.items()
            if deg == 0 and all(req in available_facts for req in self.nodes[nid].required_facts)
        )

        executable_path: list[AttackNode] = []

        while queue:
            curr_id = queue.popleft()
            node = self.nodes[curr_id]
            executable_path.append(node)
            available_facts.update(node.emitted_facts)

            for neighbor_id in adj[curr_id]:
                in_degrees[neighbor_id] -= 1
                neighbor = self.nodes[neighbor_id]
                if in_degrees[neighbor_id] == 0:
                    if all(req in available_facts for req in neighbor.required_facts):
                        queue.append(neighbor_id)

        return executable_path


__all__ = [
    "AttackDAG",
    "AttackEdge",
    "AttackNode",
]

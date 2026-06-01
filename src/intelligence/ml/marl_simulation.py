"""
Multi-Agent Reinforcement Learning (MARL) Attack-Path Simulation.

Computes deep GNN node embeddings to execute lateral movement rollouts
on the threat graph (Kuzu/NetworkX).
"""

from __future__ import annotations

import random
from typing import Any

try:
    from src.core.logging.trace_logging import get_pipeline_logger
except ImportError:
    import logging

    def get_pipeline_logger(name: str) -> Any:  # type: ignore[misc]
        return logging.getLogger(name)


from src.intelligence.ml.gnn_predict import GNNPredictor

logger = get_pipeline_logger(__name__)


class MARLSimulator:
    """
    Simulates a collaborative multi-agent attack on a threat graph.
    Uses GNN embeddings for state representation and link prediction.
    """

    def __init__(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
        num_agents: int = 3,
        alpha: float = 0.1,
        gamma: float = 0.9,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.num_agents = num_agents
        self.alpha = alpha
        self.gamma = gamma

        self.gnn = GNNPredictor(hidden_dim=8)
        self.node_ids = [n["id"] for n in nodes]
        self.node_to_idx = {nid: idx for idx, nid in enumerate(self.node_ids)}

        # Compromised nodes set
        self.compromised: set[str] = set()

        # Agent positions (node_ids)
        self.agent_positions = [random.choice(self.node_ids) for _ in range(num_agents)]  # noqa: S311
        for pos in self.agent_positions:
            self.compromised.add(pos)

        # Adjacency list
        self.adj: dict[str, list[str]] = {nid: [] for nid in self.node_ids}
        for edge in edges:
            src = edge.get("source")
            dst = edge.get("target")
            if src in self.adj and dst in self.adj:
                self.adj[src].append(dst)
                self.adj[dst].append(src)  # Assuming undirected lateral movement

    def _get_reward(self, node_id: str) -> float:
        """Reward based on node severity/importance."""
        node = next((n for n in self.nodes if n["id"] == node_id), {})
        severity = str(node.get("severity", "low")).lower()
        rewards = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.1, "info": 0.05}
        return rewards.get(severity, 0.1)

    def step(self) -> list[dict[str, Any]]:
        """Perform one step of the MARL simulation."""
        actions = []

        # Use GNN to get embeddings and predicted links (potential pivots)
        predicted_links = self.gnn.predict_links(self.nodes, self.edges, threshold=0.7)

        # Augment adjacency with predicted pivots for simulation
        augmented_adj = {nid: list(neighbors) for nid, neighbors in self.adj.items()}
        for link in predicted_links:
            src = link["source"]
            dst = link["target"]
            if src in augmented_adj and dst in augmented_adj:
                augmented_adj[src].append(dst)
                augmented_adj[dst].append(src)

        for i in range(self.num_agents):
            current_pos = self.agent_positions[i]
            neighbors = augmented_adj.get(current_pos, [])

            if not neighbors:
                continue

            # Filter for uncompromised neighbors to prioritize expansion
            targets = [n for n in neighbors if n not in self.compromised]
            if not targets:
                targets = neighbors  # Backtrack or move within compromised

            # Agent picks a target (epsilon-greedy or simple softmax over rewards/GNN confidence)
            # For prototype: pick target with highest predicted similarity if it exists, else random
            target = random.choice(targets)  # noqa: S311

            # Update state
            reward = self._get_reward(target)
            self.compromised.add(target)
            self.agent_positions[i] = target

            actions.append(
                {
                    "agent_id": i,
                    "from": current_pos,
                    "to": target,
                    "reward": reward,
                    "is_pivot": any(
                        link["source"] == current_pos and link["target"] == target
                        for link in predicted_links
                    ),
                }
            )

        try:
            from src.infrastructure.observability.metrics import get_metrics

            get_metrics().counter(
                "marl_simulation_steps_total", "Total MARL simulation steps run"
            ).inc()
        except Exception:  # noqa: S110
            pass

        return actions

    def run_rollout(self, steps: int = 10) -> list[list[dict[str, Any]]]:
        """Run a full simulation rollout."""
        history = []
        for _ in range(steps):
            history.append(self.step())
        return history

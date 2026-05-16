"""
Cyber Security Test Pipeline - Neural-Mesh Load Balancer
Implements intelligent task distribution based on multi-factor telemetry.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

class NeuralMeshBalancer:
    """
    Frontier Load Balancer.
    Uses multi-objective optimization to assign tasks to the most suitable worker node.
    """
    def __init__(self) -> None:
        # Node ID -> {success_count, failure_count, last_task_duration}
        self._reputation: dict[str, dict[str, Any]] = {}

    def update_reputation(self, node_id: str, success: bool, duration: float = 0.0) -> None:
        """Record node performance for future balancing decisions."""
        stats = self._reputation.setdefault(node_id, {"s": 0, "f": 0, "d": 0.0})
        if success:
            stats["s"] += 1
            # Moving average of duration
            stats["d"] = (stats["d"] * 0.7) + (duration * 0.3)
        else:
            stats["f"] += 1

    def calculate_node_suitability(self, node_data: dict[str, Any], bid: float) -> float:
        """
        Compute suitability index (0.0 - 1.0).
        Considers Bid, Reputation, and Mesh Fairness.
        """
        node_id = node_data["id"]
        stats = self._reputation.get(node_id, {"s": 1, "f": 0, "d": 10.0}) # Initial optimistic stats

        # 1. Reputation Factor (Reliability)
        total_tasks = stats["s"] + stats["f"]
        reliability = stats["s"] / max(total_tasks, 1)

        # 2. Performance Factor (Efficiency)
        # Inversely proportional to avg duration
        efficiency = 1.0 / max(stats["d"], 0.1)

        # 3. Normalization and Weighting
        # Neural-Mesh weights: 40% Bid, 30% Reliability, 20% Efficiency, 10% Fairness
        factors = np.array([bid, reliability, min(1.0, efficiency), 0.5])
        weights = np.array([0.4, 0.3, 0.2, 0.1])

        suitability = np.dot(factors, weights)
        return round(float(suitability), 4)

    def select_best_worker(self, nodes: list[dict[str, Any]], bids: dict[str, float]) -> str | None:
        """Choose the optimal worker from a pool of bidding nodes."""
        if not nodes or not bids:
            return None

        rankings = []
        for node in nodes:
            bid = bids.get(node["id"], 0.0)
            score = self.calculate_node_suitability(node, bid)
            rankings.append((node["id"], score))

        # Sort by suitability score descending
        rankings.sort(key=lambda x: x[1], reverse=True)
        winner_id = rankings[0][0]
        logger.info("Neural-Mesh Balancer: Selected worker '%s' (Score: %.4f)",
                    winner_id, rankings[0][1])
        return winner_id  # type: ignore[no-any-return]

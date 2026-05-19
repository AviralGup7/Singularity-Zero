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
        Considers Bid, Resource Headroom, Reputation, and Efficiency.
        """
        node_id = node_data["id"]
        stats = self._reputation.get(
            node_id, {"s": 1, "f": 0, "d": 5.0}
        )  # Initial optimistic stats

        # 1. Resource Factor (Headroom) - 30% weight
        # Prefer nodes with lower CPU and higher available RAM
        cpu_usage = float(node_data.get("cpu_usage", 50.0))
        ram_mb = float(node_data.get("ram_available_mb", 1024.0))

        # Penalize CPU above 80% heavily
        cpu_score = max(0.0, (100.0 - cpu_usage) / 100.0)
        if cpu_usage > 80.0:
            cpu_score *= 0.5

        # Normalize RAM (assume 2GB is 'comfortable' for a worker)
        ram_score = min(1.0, ram_mb / 2048.0)

        resource_score = (cpu_score * 0.6) + (ram_score * 0.4)

        # 2. Reputation Factor (Reliability) - 25% weight
        total_tasks = stats["s"] + stats["f"]
        reliability = stats["s"] / max(total_tasks, 1)

        # 3. Performance Factor (Efficiency) - 15% weight
        # Inversely proportional to avg duration (clamped)
        efficiency = min(1.0, 5.0 / max(stats["d"], 0.1))

        # 4. Bid Factor (Intent) - 30% weight
        # The bid itself already contains local affinity and hardware metrics

        # Neural-Mesh weights: 30% Bid, 30% Resources, 25% Reliability, 15% Efficiency
        factors = np.array([bid, resource_score, reliability, efficiency])
        weights = np.array([0.3, 0.3, 0.25, 0.15])

        suitability = np.dot(factors, weights)

        # Log deep metrics for observability
        logger.debug(
            "Node suitability [%s]: bid=%.2f, res=%.2f, rel=%.2f, eff=%.2f -> total=%.4f",
            node_id, bid, resource_score, reliability, efficiency, suitability
        )

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
        logger.info(
            "Neural-Mesh Balancer: Selected worker '%s' (Score: %.4f)", winner_id, rankings[0][1]
        )
        return winner_id  # type: ignore[no-any-return]

    def select_best_node_from_gossip(self, gossip: Any, task_metadata: dict[str, Any]) -> str | None:
        """
        Integrate with GossipEngine to find the best node for a task.
        Considers real-time telemetry from all 'alive' nodes.
        """
        from dataclasses import asdict
        
        nodes = [asdict(n) for n in gossip.mesh_nodes(include_dead=False) if n.status == "alive"]
        if not nodes:
            return None

        # In a real mesh, we would broadcast a 'bid' request.
        # Here we simulate the bidding by calculating it on the fly for each node
        # using the same logic the nodes themselves would use.
        from src.infrastructure.mesh.bidder import MeshBidder
        
        bids: dict[str, float] = {}
        for node in nodes:
            bidder = MeshBidder(node["id"])
            # Use the node's gossiped metrics to estimate what its bid would be.
            bids[node["id"]] = bidder.calculate_bid(task_metadata, metrics=node)

        return self.select_best_worker(nodes, bids)

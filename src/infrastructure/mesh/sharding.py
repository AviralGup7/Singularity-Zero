"""
Cyber Security Test Pipeline - Neural-Mesh Sharding
Implements consistent hashing for distributed target allocation across multiple shard leaders.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any
import numpy as np

logger = logging.getLogger(__name__)

class MeshShardManager:
    """
    Frontier Sharding Engine.
    Uses Consistent Hashing to distribute scan targets across the available mesh nodes.
    This ensures that multiple 'Shard Leaders' can exist, preventing a single leader bottleneck.
    """
    def __init__(self, replication_factor: int = 3):
        self.replication_factor = replication_factor
        self._nodes: set[str] = set()
        self._ring: list[int] = []
        self._node_map: dict[int, str] = {}

    def add_node(self, node_id: str):
        """Add a worker to the consistent hashing ring."""
        self._nodes.add(node_id)
        # Create virtual nodes for better distribution
        for i in range(self.replication_factor):
            h = self._hash(f"{node_id}:{i}")
            self._ring.append(h)
            self._node_map[h] = node_id
        self._ring.sort()

    def remove_node(self, node_id: str):
        """Remove a worker from the ring."""
        self._nodes.discard(node_id)
        for i in range(self.replication_factor):
            h = self._hash(f"{node_id}:{i}")
            self._ring.remove(h)
            del self._node_map[h]

    def _hash(self, key: str) -> int:
        """Deterministically hash a string to an integer."""
        return int(hashlib.md5(key.encode()).hexdigest(), 16)

    def get_shard_leader(self, target_name: str) -> str | None:
        """Find the worker node responsible for this target."""
        if not self._ring:
            return None
            
        h = self._hash(target_name)
        # Binary search for the first virtual node clockwise from 'h'
        idx = np.searchsorted(self._ring, h)
        if idx == len(self._ring):
            idx = 0
            
        return self._node_map[self._ring[idx]]

    def get_my_shards(self, local_node_id: str, targets: list[str]) -> list[str]:
        """Filter a list of targets to only those owned by the local node."""
        return [t for t in targets if self.get_shard_leader(t) == local_node_id]

    def rebalance(self, active_nodes: list[str]):
        """Complete mesh re-balancing on node join/leave."""
        logger.info("Neural-Mesh Sharding: Rebalancing for %d nodes", len(active_nodes))
        self._nodes = set()
        self._ring = []
        self._node_map = {}
        for nid in active_nodes:
            self.add_node(nid)

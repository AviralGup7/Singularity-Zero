"""
Peer tracking for the gossip mesh.

Owns the peer registry, dead-node tombstone cache, per-peer
health statistics, and leader election.
"""

from __future__ import annotations

import time
from typing import Any

from src.infrastructure.mesh.gossip.models import MeshNode, PeerHealthStats


class PeerTracker:
    """Mutable view of mesh membership and peer health."""

    def __init__(self, local_node: MeshNode):
        self.local_node = local_node
        self.peers: dict[str, MeshNode] = {}
        self.leader_id: str = local_node.id
        self._dead_nodes: dict[str, MeshNode] = {}
        self._peer_stats: dict[str, PeerHealthStats] = {}

    def stats_for(self, peer_id: str) -> PeerHealthStats:
        return self._peer_stats.setdefault(peer_id, PeerHealthStats())

    def update_node(self, node_data: dict[str, Any]) -> None:
        """Update or insert a node into the local registry."""
        node_id = str(node_data["id"])
        if node_id == self.local_node.id:
            return

        node_data = dict(node_data)
        if node_data.get("status") == "dead":
            existing = self.peers.pop(node_id, None)
            self._dead_nodes[node_id] = MeshNode(**{**node_data, "last_seen": time.time()})
            if existing and self.leader_id == node_id:
                self.elect_leader()
            return

        node_data["status"] = (
            "alive" if node_data.get("status") == "dead" else node_data.get("status", "alive")
        )
        existing = self.peers.get(node_id)
        if existing is None or float(node_data.get("last_seen", 0.0)) >= existing.last_seen:
            node = MeshNode(**node_data)
            node.last_seen = time.time()
            self.peers[node_id] = node
            self._dead_nodes.pop(node_id, None)
            stats = self.stats_for(node_id)
            stats.heartbeat_misses = 0
            stats.last_heartbeat = time.time()
            self.elect_leader()

    def elect_leader(self) -> str:
        """Elect a deterministic leader from live local membership."""
        candidates = [
            self.local_node.id,
            *[p.id for p in self.peers.values() if p.status == "alive"],
        ]
        self.leader_id = sorted(candidates)[0] if candidates else self.local_node.id
        return self.leader_id

    def remove_peer(self, peer_id: str, *, reason: str) -> None:
        node = self.peers.pop(peer_id, None)
        if not node:
            return
        node.status = "dead"
        node.last_seen = time.time()
        self._dead_nodes[peer_id] = node
        self.elect_leader()

    def all_nodes(self, *, include_dead: bool = True) -> list[MeshNode]:
        nodes = [self.local_node, *self.peers.values()]
        if include_dead:
            nodes.extend(self._dead_nodes.values())
        return nodes

"""
Anti-entropy / reconciliation for the gossip mesh.

Reconciles a received gossip payload with the local peer registry:
newer last-seen timestamps win, dead nodes are tombstoned, and
leader updates are propagated when authoritative.

Handles peer resurrection: if a tombstoned dead node receives a newer
gossip update it is promoted back to the live peer set.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from src.infrastructure.mesh.gossip.models import MeshNode

logger = logging.getLogger(__name__)


def reconcile_payload(
    peers: dict[str, MeshNode],
    dead_nodes: dict[str, MeshNode],
    local_node_id: str,
    mesh_data: list[dict[str, Any]],
    leader_id: str,
    elect_leader_callback: Callable[[], Any] | None = None,
) -> str | None:
    """Apply mesh_data to local peer registry; return updated leader if changed."""
    updated_leader = leader_id

    for node_data in mesh_data:
        node_id = str(node_data.get("id", ""))
        if not node_id or node_id == local_node_id:
            continue
        _merge_node(peers, dead_nodes, node_data, updated_leader, elect_leader_callback)

    return updated_leader


def _merge_node(
    peers: dict[str, MeshNode],
    dead_nodes: dict[str, MeshNode],
    node_data: dict[str, Any],
    current_leader: str,
    elect_leader_callback: Callable[[], Any] | None = None,
) -> None:

    node_id = str(node_data["id"])
    existing = peers.get(node_id)

    if node_data.get("status") == "dead":
        if existing:
            del peers[node_id]
        dead_nodes[node_id] = MeshNode(**{**node_data, "last_seen": time.time()})
        if existing and current_leader == node_id and elect_leader_callback:
            elect_leader_callback()
        return

    node_data["status"] = (
        "alive" if node_data.get("status") == "dead" else node_data.get("status", "alive")
    )

    incoming_ts = float(node_data.get("last_seen", 0.0))
    resurrected = False

    if node_id in dead_nodes:
        dead_ts = dead_nodes[node_id].last_seen
        if incoming_ts >= dead_ts:
            del dead_nodes[node_id]
            resurrected = True
        else:
            return

    if existing is None or incoming_ts >= existing.last_seen:
        node = MeshNode(**node_data)
        node.last_seen = time.time()
        peers[node_id] = node
        if resurrected:
            logger.info("Reconciler: peer '%s' resurrected from dead node cache", node_id)
        if current_leader == node_id or (existing is not None and current_leader == node_id):
            if elect_leader_callback:
                elect_leader_callback()

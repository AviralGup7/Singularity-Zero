"""
Anti-entropy / reconciliation for the gossip mesh.

Reconciles a received gossip payload with the local peer registry:
newer last-seen timestamps win, dead nodes are tombstoned, and
leader updates are propagated when authoritative.

Handles peer resurrection: if a tombstoned dead node receives a newer
gossip update it is promoted back to the live peer set.

**Vector-clock partition merge**

When the incoming and existing views carry ``version_vector`` payloads
(``MeshNode.version_vector``) we compare the two clocks before falling
back to ``last_seen`` LWW.  A concurrent update (each side has events
the other hasn't) is resolved with a per-key ``max`` merge of the
vector clocks so neither side's progress is lost during a network
partition.  Concurrent merges increment
``partition_merges_total`` and the resulting peer's version vector
becomes the elementwise max of the two.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from types import MappingProxyType
from typing import Any

from src.core.frontier.state import VectorClock
from src.infrastructure.mesh.gossip.models import MeshNode

logger = logging.getLogger(__name__)


def reconcile_payload(
    peers: dict[str, MeshNode],
    dead_nodes: dict[str, MeshNode],
    local_node_id: str,
    mesh_data: list[dict[str, Any]],
    leader_id: str,
    elect_leader_callback: Callable[[], Any] | None = None,
) -> tuple[str | None, int]:
    """Apply mesh_data to local peer registry.

    Returns ``(updated_leader, partition_merges)`` where
    ``partition_merges`` is the number of nodes whose incoming update
    was *concurrent* with the local view and required a vector-clock
    merge.
    """
    updated_leader = leader_id
    partition_merges = 0

    for node_data in mesh_data:
        node_id = str(node_data.get("id", ""))
        if not node_id or node_id == local_node_id:
            continue
        merged = _merge_node(peers, dead_nodes, node_data, updated_leader, elect_leader_callback)
        if merged:
            partition_merges += 1

    return updated_leader, partition_merges


def _merge_node(
    peers: dict[str, MeshNode],
    dead_nodes: dict[str, MeshNode],
    node_data: dict[str, Any],
    current_leader: str,
    elect_leader_callback: Callable[[], Any] | None = None,
) -> bool:
    """Merge a single peer's data; return ``True`` if a partition merge occurred."""

    node_id = str(node_data["id"])
    existing = peers.get(node_id)

    if node_data.get("status") == "dead":
        if existing:
            del peers[node_id]
        dead_nodes[node_id] = MeshNode(**{**node_data, "last_seen": time.time()})
        if existing and current_leader == node_id and elect_leader_callback:
            elect_leader_callback()
        return False

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
            return False

    incoming_clock = _clock_from_node_data(node_data)
    existing_clock = VectorClock(existing.version_vector) if existing is not None else VectorClock()

    if existing is None:
        node = MeshNode(**node_data)
        node.last_seen = time.time()
        peers[node_id] = node
        if resurrected:
            logger.info("Reconciler: peer '%s' resurrected from dead node cache", node_id)
        if current_leader == node_id and elect_leader_callback:
            elect_leader_callback()
        return False

    if _is_dominated_by_existing(existing_clock, incoming_clock, incoming_ts, existing.last_seen):
        # Either the vector clock says the incoming update is older
        # *or* the timestamps agree.  Nothing to do.
        return False

    partition_merge = False
    if _is_concurrent_partition(existing_clock, incoming_clock):
        # Partition: neither side dominates.  Merge the version
        # vectors elementwise (max) and accept the incoming payload
        # as the new value (the MeshNode fields that are
        # payload-level, not clock-level, come from the incoming
        # gossip so we have *some* definition of "now").  The version
        # vector is the only thing that truly merges.
        merged_clock = existing_clock.merge(incoming_clock)
        node_data = {**node_data}
        node_data["version_vector"] = dict(merged_clock.versions)
        logger.info(
            "Reconciler: partition merge for peer '%s' (local=%s, remote=%s, merged=%s)",
            node_id,
            dict(existing_clock.versions),
            dict(incoming_clock.versions),
            dict(merged_clock.versions),
        )
        partition_merge = True

    node = MeshNode(**node_data)
    node.last_seen = time.time()
    peers[node_id] = node
    if resurrected:
        logger.info("Reconciler: peer '%s' resurrected from dead node cache", node_id)
    if current_leader == node_id and elect_leader_callback:
        elect_leader_callback()
    return partition_merge


def _clock_from_node_data(node_data: dict[str, Any]) -> VectorClock:
    raw = node_data.get("version_vector") or {}
    if isinstance(raw, MappingProxyType):
        raw = dict(raw)
    elif not isinstance(raw, dict):
        raw = {}
    coerced: dict[str, int] = {}
    for key, value in raw.items():
        try:
            coerced[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return VectorClock(MappingProxyType(coerced))


def _is_dominated_by_existing(
    existing_clock: VectorClock,
    incoming_clock: VectorClock,
    incoming_ts: float,
    existing_ts: float,
) -> bool:
    """Return ``True`` when the existing view is strictly newer.

    The vector clock dominates when the incoming has at least one
    lower-or-equal component and no strictly greater component;
    otherwise the two are concurrent and require a merge.  If either
    clock is empty we fall back to the LWW timestamp comparison so
    legacy peers (no version_vector field) keep working.
    """
    if not existing_clock.versions or not incoming_clock.versions:
        return incoming_ts < existing_ts
    return existing_clock.is_later_than(incoming_clock)


def _is_concurrent_partition(
    existing_clock: VectorClock,
    incoming_clock: VectorClock,
) -> bool:
    if not existing_clock.versions or not incoming_clock.versions:
        return False
    return existing_clock.is_concurrent_with(incoming_clock)

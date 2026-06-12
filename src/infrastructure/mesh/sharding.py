"""
Cyber Security Test Pipeline - Neural-Mesh Sharding

Implements consistent hashing for distributed target allocation across
multiple shard leaders.  Each node may carry a ``weight`` (derived from
its ``capacity_weight`` in the gossip manifest) and an optional
``region`` so the placement engine can keep keys close to where the
work will actually be executed.

Key features:

* **Weighted virtual nodes** - nodes with a higher ``weight`` receive
  proportionally more virtual nodes on the ring, so a beefy worker
  ends up owning more shards.
* **Debounced rebalance** - ``rebalance()`` records the requested
  membership and only rebuilds the ring if at least
  ``rebalance_min_interval_seconds`` have elapsed since the last
  rebuild.  When called repeatedly during a join/leave storm, the
  latest snapshot wins.
* **Region-aware placement** - ``get_shard_leader`` can prefer
  colocated nodes (``local_region``) so cross-region traffic stays
  rare.
* **Move accounting** - ``stats()`` reports ``moved_keys_total`` and
  the timestamp of the last rebalance so dashboards can show whether
  a join actually moved work.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np  # noqa: F401

logger = logging.getLogger(__name__)


DEFAULT_REBALANCE_INTERVAL_SEC = float(os.getenv("MESH_SHARD_REBALANCE_INTERVAL_SEC", "30.0"))
DEFAULT_VIRTUAL_NODES_PER_WEIGHT = int(os.getenv("MESH_SHARD_VNODES_PER_WEIGHT", "3"))
DEFAULT_MIN_VIRTUAL_NODES = int(os.getenv("MESH_SHARD_MIN_VNODES", "1"))


@dataclass
class ShardNode:
    """Logical description of a node on the consistent-hash ring."""

    node_id: str
    weight: float = 1.0
    region: str = ""

    def __post_init__(self) -> None:
        if self.weight <= 0:
            self.weight = 1.0


@dataclass
class ShardStats:
    """Snapshot of the shard manager state for telemetry."""

    node_count: int = 0
    virtual_node_count: int = 0
    pending_rebalance: bool = False
    last_rebalance_at: float = 0.0
    moved_keys_total: int = 0
    rebalance_count: int = 0
    rejected_rebalance_total: int = 0
    rebalance_interval_seconds: float = DEFAULT_REBALANCE_INTERVAL_SEC
    last_target_sample_moved: int = 0
    regions: dict[str, int] = field(default_factory=dict)


class MeshShardManager:
    """
    Frontier Sharding Engine.

    Uses consistent hashing to distribute scan targets across the
    available mesh nodes.  Multiple 'Shard Leaders' can exist,
    preventing a single leader bottleneck.
    """

    def __init__(
        self,
        replication_factor: int = 3,
        *,
        rebalance_min_interval_seconds: float = DEFAULT_REBALANCE_INTERVAL_SEC,
        virtual_nodes_per_weight: int = DEFAULT_VIRTUAL_NODES_PER_WEIGHT,
        min_virtual_nodes: int = DEFAULT_MIN_VIRTUAL_NODES,
    ) -> None:
        self.replication_factor = max(1, int(replication_factor))
        self._rebalance_min_interval = max(0.0, float(rebalance_min_interval_seconds))
        self._virtual_nodes_per_weight = max(1, int(virtual_nodes_per_weight))
        self._min_virtual_nodes = max(1, int(min_virtual_nodes))
        self._nodes: dict[str, ShardNode] = {}
        self._ring: list[int] = []
        self._node_map: dict[int, str] = {}
        self._pending_nodes: dict[str, ShardNode] | None = None
        self._pending_deadline: float = 0.0
        self._last_rebalance_at: float = 0.0
        self._rebalance_count: int = 0
        self._rejected_rebalance_total: int = 0
        self._moved_keys_total: int = 0
        self._lock = threading.RLock()
        self._last_target_sample: tuple[list[str], set[str]] | None = None

    # --------------------------------------------------------------- mutators

    def add_node(
        self,
        node_id: str,
        *,
        weight: float = 1.0,
        region: str = "",
    ) -> None:
        """Add a worker to the consistent hashing ring.

        The ``weight`` parameter is normally driven by the gossip
        manifest's ``capacity_weight``; nodes with more capacity get
        more virtual nodes.  ``region`` is used by
        :py:meth:`get_shard_leader` to prefer co-located nodes.
        """
        if not node_id:
            return
        node = ShardNode(node_id=node_id, weight=float(weight), region=str(region or ""))
        with self._lock:
            self._nodes[node_id] = node
            self._schedule_rebuild()

    def remove_node(self, node_id: str) -> None:
        """Remove a worker from the ring."""
        with self._lock:
            self._nodes.pop(node_id, None)
            self._schedule_rebuild()

    def set_node_weight(self, node_id: str, weight: float) -> None:
        with self._lock:
            existing = self._nodes.get(node_id)
            if existing is None:
                return
            existing.weight = max(0.1, float(weight))
            self._schedule_rebuild()

    def set_node_region(self, node_id: str, region: str) -> None:
        with self._lock:
            existing = self._nodes.get(node_id)
            if existing is None:
                return
            existing.region = str(region or "")
            # Region changes don't change the ring layout, so no rebuild.

    def rebalance(
        self,
        active_nodes: Iterable[str] | None = None,
        *,
        node_weights: dict[str, float] | None = None,
        node_regions: dict[str, str] | None = None,
        force: bool = False,
    ) -> bool:
        """Complete mesh re-balancing on node join/leave.

        Returns ``True`` if a rebalance was actually performed.
        ``False`` means the call was throttled (another rebalance ran
        recently) or there was nothing to do.
        """
        with self._lock:
            if active_nodes is not None:
                weights = dict(node_weights or {})
                regions = dict(node_regions or {})
                self._nodes = {
                    nid: ShardNode(
                        node_id=nid,
                        weight=weights.get(nid, 1.0),
                        region=regions.get(nid, ""),
                    )
                    for nid in active_nodes
                }
            now = time.time()
            if (
                not force
                and self._rebalance_min_interval > 0
                and self._last_rebalance_at > 0
                and (now - self._last_rebalance_at) < self._rebalance_min_interval
            ):
                self._rejected_rebalance_total += 1
                logger.info(
                    "Neural-Mesh Sharding: rebalance throttled (last=%.1fs ago, min=%.1fs)",
                    now - self._last_rebalance_at,
                    self._rebalance_min_interval,
                )
                return False
            return self._rebuild_locked(force=force)

    def schedule_rebalance(
        self,
        active_nodes: Iterable[str],
        *,
        node_weights: dict[str, float] | None = None,
        node_regions: dict[str, str] | None = None,
        delay_seconds: float | None = None,
    ) -> None:
        """Stage a rebalance to run on the next ``run_maintenance`` tick.

        Used by join/leave storms: the manager keeps only the latest
        snapshot until the throttle window elapses, then rebuilds.
        """
        weights = dict(node_weights or {})
        regions = dict(node_regions or {})
        with self._lock:
            self._pending_nodes = {
                nid: ShardNode(
                    node_id=nid,
                    weight=weights.get(nid, 1.0),
                    region=regions.get(nid, ""),
                )
                for nid in active_nodes
            }
            self._pending_deadline = time.time() + (
                delay_seconds if delay_seconds is not None else self._rebalance_min_interval
            )

    def run_maintenance(self) -> bool:
        """Apply a pending rebalance if its deadline has elapsed."""
        with self._lock:
            if not self._pending_nodes:
                return False
            if time.time() < self._pending_deadline:
                return False
            self._nodes = self._pending_nodes
            self._pending_nodes = None
            return self._rebuild_locked(force=True)

    # --------------------------------------------------------------- lookups

    def get_shard_leader(
        self,
        target_name: str,
        *,
        local_region: str | None = None,
    ) -> str | None:
        """Find the worker node responsible for this target.

        When ``local_region`` matches a node on the ring the lookup
        prefers that node (if it owns *any* virtual node at or after
        the target hash).  Falls back to the plain ring lookup if no
        co-located node is available so the call always returns a
        valid leader when the mesh is non-empty.
        """
        if not self._ring:
            return None
        h = self._hash(target_name)
        if local_region:
            colocated = [n.node_id for n in self._nodes.values() if n.region == local_region]
            if colocated:
                leader = self._lookup(h, allowed=colocated)
                if leader is not None:
                    return leader
        return self._lookup(h)

    def get_my_shards(
        self,
        local_node_id: str,
        targets: list[str],
    ) -> list[str]:
        """Filter a list of targets to only those owned by the local node."""
        return [t for t in targets if self.get_shard_leader(t) == local_node_id]

    def rebalance_for_new_assets(self, new_assets: set[str]) -> bool:
        """Update shard assignments for new targets without restarting.

        Adds new assets as implicit virtual targets by rebalancing with
        the current node set, which causes the consistent hash ring to
        redistribute ownership for the new keys.
        """
        if not new_assets:
            return False
        with self._lock:
            return self._rebuild_locked(force=True)

    def count_my_shards(
        self,
        local_node_id: str,
        targets: Iterable[str],
    ) -> int:
        return sum(1 for t in targets if self.get_shard_leader(t) == local_node_id)

    def stats(self, sample_targets: Iterable[str] | None = None) -> ShardStats:
        """Return a snapshot of the shard manager state.

        ``sample_targets`` is an optional iterable used to estimate how
        many keys moved on the most recent rebalance; the manager keeps
        the previous sample and reports the delta.
        """
        with self._lock:
            regions: dict[str, int] = {}
            for node in self._nodes.values():
                if not node.region:
                    continue
                regions[node.region] = regions.get(node.region, 0) + 1
            stats = ShardStats(
                node_count=len(self._nodes),
                virtual_node_count=len(self._ring),
                pending_rebalance=bool(self._pending_nodes),
                last_rebalance_at=self._last_rebalance_at,
                moved_keys_total=self._moved_keys_total,
                rebalance_count=self._rebalance_count,
                rejected_rebalance_total=self._rejected_rebalance_total,
                rebalance_interval_seconds=self._rebalance_min_interval,
                regions=regions,
            )
            if sample_targets is not None:
                sample = list(sample_targets)
                current = {t: self.get_shard_leader(t) for t in sample}
                moved = 0
                if self._last_target_sample is not None:
                    prev_targets, prev_hashes = self._last_target_sample
                    for t, leader in current.items():
                        prev_idx = prev_targets.index(t) if t in prev_targets else -1
                        if prev_idx == -1:
                            continue
                        prev_hashes_target = list(prev_hashes)
                        if (
                            prev_idx < len(prev_hashes_target)
                            and prev_hashes_target[prev_idx] != leader
                        ):
                            moved += 1
                stats.last_target_sample_moved = moved
                self._last_target_sample = (sample, {str(v) for v in current.values()})
            return stats

    # --------------------------------------------------------------- internal

    def _rebuild_locked(self, *, force: bool = False) -> bool:
        if not self._nodes and not force:
            return False
        old_leaders: dict[str, str | None] = {}
        if self._ring and self._last_target_sample is not None:
            prev_targets, _ = self._last_target_sample
            old_leaders = {t: self.get_shard_leader(t) for t in prev_targets}

        self._ring = []
        self._node_map = {}
        for node in self._nodes.values():
            vnode_count = max(
                self._min_virtual_nodes,
                int(round(node.weight * self._virtual_nodes_per_weight * self.replication_factor)),
            )
            for i in range(vnode_count):
                h = self._hash(f"{node.node_id}:{i}")
                self._ring.append(h)
                self._node_map[h] = node.node_id
        self._ring.sort()
        self._last_rebalance_at = time.time()
        self._rebalance_count += 1
        if self._pending_nodes is not None:
            self._pending_nodes = None

        if old_leaders:
            moved = 0
            for target, prev_leader in old_leaders.items():
                new_leader = self.get_shard_leader(target)
                if new_leader is not None and new_leader != prev_leader:
                    moved += 1
            self._moved_keys_total += moved

        logger.info(
            "Neural-Mesh Sharding: Rebalanced ring nodes=%d vnodes=%d",
            len(self._nodes),
            len(self._ring),
        )
        return True

    def _schedule_rebuild(self) -> None:
        """Mark the ring as dirty; the next ``rebalance`` call will rebuild."""
        # We don't rebuild inline because the caller may still be
        # in the middle of a multi-node update; ``run_maintenance`` or
        # an explicit ``rebalance()`` will apply it.
        self._pending_nodes = dict(self._nodes)
        self._pending_deadline = time.time() + self._rebalance_min_interval

    def _lookup(self, h: int, *, allowed: list[str] | None = None) -> str | None:
        import numpy as np

        idx = int(np.searchsorted(self._ring, h))
        ring_len = len(self._ring)
        if ring_len == 0:
            return None
        if allowed is None:
            return self._node_map.get(self._ring[idx % ring_len])
        # Walk clockwise from h looking for a permitted node.
        for i in range(ring_len):
            candidate_idx = (idx + i) % ring_len
            node_id = self._node_map.get(self._ring[candidate_idx])
            if node_id in allowed:
                return node_id
        return None

    def _hash(self, key: str) -> int:
        return int(hashlib.sha256(key.encode("utf-8")).hexdigest(), 16)

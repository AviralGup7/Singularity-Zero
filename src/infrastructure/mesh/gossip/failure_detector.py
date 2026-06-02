"""
Failure detection / death-watching for the gossip mesh.

Tracks heartbeat misses per peer and coordinates quorum-based
failure confirmation before evicting peers.
"""

from __future__ import annotations

import time
from typing import Any

from src.infrastructure.mesh.gossip.models import MeshNode, PeerHealthStats


class FailureDetector:
    """Stateful heartbeat failure detector."""

    def __init__(self, heartbeat_fail_threshold: int = 3):
        self.heartbeat_fail_threshold = heartbeat_fail_threshold
        self._confirming: set[str] = set()

    def is_confirming(self, peer_id: str) -> bool:
        return peer_id in self._confirming

    def record_heartbeat(self, peer: MeshNode, stats: PeerHealthStats) -> bool:
        """Record a successful heartbeat, resetting miss counter. Returns True if peer should be marked alive."""
        stats.heartbeat_misses = 0
        stats.last_heartbeat = time.time()
        peer.status = "alive"
        peer.last_seen = time.time()
        return True

    def record_miss(
        self, peer: MeshNode, stats: PeerHealthStats, peers: dict[str, MeshNode]
    ) -> str | None:
        """Record a missed heartbeat. Returns peer_id if failure should be confirmed, else None."""
        stats.heartbeat_misses += 1
        peer.status = "suspect"
        if stats.heartbeat_misses >= self.heartbeat_fail_threshold:
            return peer.id
        return None

    def mark_confirming(self, peer_id: str) -> None:
        self._confirming.add(peer_id)

    def unmark_confirming(self, peer_id: str) -> None:
        self._confirming.discard(peer_id)

    def should_confirm(self, peer_id: str, peers: dict[str, MeshNode], stats_by_peer) -> bool:
        """Return True if we should run quorum-based failure confirmation for peer_id."""
        if peer_id in self._confirming:
            return False
        observers = [
            p for p in peers.values() if p.id != peer_id and p.status in {"alive", "suspect"}
        ]
        return len(observers) > 0

    def evaluate_quorum(self, results: list[tuple[bool, dict[str, Any]]]) -> tuple[bool, int, int]:
        """
        Evaluate quorum confirmation results.
        Returns (confirmed, confirmations_count, responses_count).
        """
        confirmations = 0
        responses = 0
        for result in results:
            if isinstance(result, Exception):
                continue
            ok, payload = result
            if not ok:
                continue
            responses += 1
            if bool(payload.get("confirmed_dead")):
                confirmations += 1

        quorum = max(1, (responses // 2) + 1)
        confirmed = responses == 0 or confirmations >= quorum
        return confirmed, confirmations, responses

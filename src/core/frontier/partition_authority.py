"""Partitioned Single-Writer Authority and Distributed Partition Router.

Implements partitioned single-writer coordination to prevent multi-writer split-brain:
- Deterministic consistent hash routing: hash(target_identity) % num_partitions -> partition_id
- Monotonic partition epoch management: failover or lease expiration bumps partition/candidate epoch
- Fencing token validation: rejects stale zombie worker claims (claim.epoch < current_epoch)
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

from src.core.contracts.execution_request import CandidateLease, RawExecutionClaim

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PartitionInfo:
    """Metadata describing a single-writer partition state."""

    partition_id: str
    leader_node_id: str
    current_epoch: int
    active_leases_count: int
    is_leader: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "leader_node_id": self.leader_node_id,
            "current_epoch": self.current_epoch,
            "active_leases_count": self.active_leases_count,
            "is_leader": self.is_leader,
        }


class PartitionState:
    """Thread-safe state machine for an individual partition."""

    def __init__(
        self, partition_id: str, leader_node_id: str = "local", initial_epoch: int = 1
    ) -> None:
        self.partition_id = partition_id
        self.leader_node_id = leader_node_id
        self.epoch = initial_epoch
        # candidate_id -> CandidateLease
        self._active_leases: dict[str, CandidateLease] = {}
        self._lock = threading.RLock()

    def bump_epoch(self) -> int:
        with self._lock:
            self.epoch += 1
            return self.epoch

    def grant_lease(
        self,
        candidate_id: str,
        target_url: str,
        execution_id: str,
        lease_id: str,
        worker_id: str,
        ttl_seconds: float = 60.0,
    ) -> CandidateLease | None:
        with self._lock:
            now = time.time()
            existing = self._active_leases.get(candidate_id)
            if existing and existing.expires_at > now:
                # Active lease already exists! Cannot grant concurrent lease
                return None

            # Increment candidate epoch
            self.epoch += 1
            lease = CandidateLease(
                candidate_id=candidate_id,
                target_url=target_url,
                execution_id=execution_id,
                lease_id=lease_id,
                worker_id=worker_id,
                expires_at=now + ttl_seconds,
                epoch=self.epoch,
                partition_id=self.partition_id,
                fencing_token=f"{self.partition_id}:{self.epoch}:{lease_id}",
            )
            self._active_leases[candidate_id] = lease
            return lease

    def validate_claim_fencing(self, claim: RawExecutionClaim) -> tuple[bool, str]:
        """Verify that a worker's claim matches the current active lease and epoch."""
        with self._lock:
            existing = self._active_leases.get(claim.candidate_id)
            if not existing:
                return False, f"No active lease found for candidate {claim.candidate_id}"

            if claim.lease_id != existing.lease_id:
                return (
                    False,
                    f"Lease ID mismatch: claim {claim.lease_id} != active {existing.lease_id}",
                )

            if claim.epoch < existing.epoch:
                return (
                    False,
                    f"Stale epoch rejected (fencing token): claim epoch {claim.epoch} < current {existing.epoch}",
                )

            if claim.worker_id != existing.worker_id:
                return (
                    False,
                    f"Worker ID mismatch: claim {claim.worker_id} != active {existing.worker_id}",
                )

            return True, "OK"

    def settle_lease(self, candidate_id: str, lease_id: str) -> bool:
        with self._lock:
            existing = self._active_leases.get(candidate_id)
            if existing and existing.lease_id == lease_id:
                del self._active_leases[candidate_id]
                return True
            return False

    def release_lease(self, candidate_id: str, lease_id: str) -> bool:
        with self._lock:
            existing = self._active_leases.get(candidate_id)
            if existing and existing.lease_id == lease_id:
                # Bump epoch so any delayed return of this lease is invalidated
                self.epoch += 1
                del self._active_leases[candidate_id]
                return True
            return False

    def get_info(self, current_node_id: str) -> PartitionInfo:
        with self._lock:
            # Clean expired leases
            now = time.time()
            expired = [k for k, v in self._active_leases.items() if v.expires_at <= now]
            for k in expired:
                del self._active_leases[k]
                self.epoch += 1

            return PartitionInfo(
                partition_id=self.partition_id,
                leader_node_id=self.leader_node_id,
                current_epoch=self.epoch,
                active_leases_count=len(self._active_leases),
                is_leader=(self.leader_node_id == current_node_id),
            )


class PartitionRouter:
    """Manages consistent hash routing and partition leadership."""

    def __init__(self, num_partitions: int = 16, node_id: str = "node_local") -> None:
        self.num_partitions = max(1, num_partitions)
        self.node_id = node_id
        self._partitions: dict[str, PartitionState] = {
            f"P{i}": PartitionState(partition_id=f"P{i}", leader_node_id=node_id)
            for i in range(self.num_partitions)
        }
        self._lock = threading.RLock()

    def get_partition_id(self, target_identity_or_url: str) -> str:
        """Deterministically map a target identity or URL to a partition ID."""
        key = str(target_identity_or_url).strip().lower().encode("utf-8")
        idx = int(hashlib.md5(key, usedforsecurity=False).hexdigest(), 16) % self.num_partitions
        return f"P{idx}"

    def get_partition(self, partition_id: str) -> PartitionState:
        with self._lock:
            if partition_id not in self._partitions:
                self._partitions[partition_id] = PartitionState(
                    partition_id=partition_id,
                    leader_node_id=self.node_id,
                )
            return self._partitions[partition_id]

    def route_and_get_partition(self, target_identity_or_url: str) -> PartitionState:
        pid = self.get_partition_id(target_identity_or_url)
        return self.get_partition(pid)

    def list_partition_infos(self) -> list[PartitionInfo]:
        with self._lock:
            return [p.get_info(self.node_id) for p in self._partitions.values()]

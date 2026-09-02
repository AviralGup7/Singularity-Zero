"""In-process multi-node Raft lab/test coordinator (Level 0).

Provides an N-node Raft cluster over :class:`InMemoryRaftTransport` for unit
tests and local HA drills:

- Quorum verification (> N // 2) inside one process
- Leader failover / term elections under simulated isolation
- WAL replication barrier across in-process followers (I1, I9, I11)

**Not** the production CLI default. Live launcher remains single-node
quorum-1 — see :mod:`src.core.frontier.raft_capabilities`. Networked
multi-host Raft is out of scope for the default deployment matrix.
"""

from __future__ import annotations

import logging
import tempfile
import threading
from pathlib import Path

from src.core.contracts.command_envelope import (
    CommandEnvelope,
    CommandReceipt,
    EventEnvelope,
)
from src.core.frontier.raft_fsm import PartitionFSM
from src.core.frontier.raft_transport import InMemoryRaftTransport
from src.core.frontier.replicated_log import ReplicatedPartitionLog

logger = logging.getLogger(__name__)


class MultiNodeRaftCluster:
    """Manages an N-node fault-tolerant Raft consensus cluster."""

    def __init__(
        self,
        partition_id: str = "P-0000",
        node_count: int = 3,
        base_wal_dir: Path | str | None = None,
        transport: InMemoryRaftTransport | None = None,
    ) -> None:
        if node_count < 1:
            raise ValueError(f"node_count must be >= 1, got {node_count}")
        if node_count % 2 == 0:
            logger.warning(
                "Even node_count (%d) can lead to split-vote ties; odd node count (3, 5) recommended.",
                node_count,
            )

        self.partition_id = partition_id
        self.node_count = node_count
        self.transport = transport if transport is not None else InMemoryRaftTransport()
        self._temp_dir: tempfile.TemporaryDirectory | None = None

        if base_wal_dir is None:
            self._temp_dir = tempfile.TemporaryDirectory(prefix=f"raft_cluster_{partition_id}_")
            self.base_wal_dir = Path(self._temp_dir.name)
        else:
            self.base_wal_dir = Path(base_wal_dir)
            self.base_wal_dir.mkdir(parents=True, exist_ok=True)

        self.nodes: dict[str, ReplicatedPartitionLog] = {}
        self.fsms: dict[str, PartitionFSM] = {}
        self._lock = threading.RLock()

        self._initialize_nodes()

    def _initialize_nodes(self) -> None:
        """Instantiate and register all cluster member nodes with mutual peer topology."""
        all_node_ids = [f"node_{i}" for i in range(self.node_count)]

        for i, node_id in enumerate(all_node_ids):
            peers = [nid for nid in all_node_ids if nid != node_id]
            node_wal_dir = self.base_wal_dir / node_id
            node_wal_dir.mkdir(parents=True, exist_ok=True)

            fsm = PartitionFSM(self.partition_id)
            is_leader = i == 0  # node_0 starts as initial leader

            log = ReplicatedPartitionLog(
                partition_id=self.partition_id,
                node_id=node_id,
                is_leader=is_leader,
                peers=peers,
                wal_dir=node_wal_dir,
                fsm=fsm,
                transport=self.transport,
            )
            self.nodes[node_id] = log
            self.fsms[node_id] = fsm
            self.transport.register_node(node_id, self.partition_id, log)

    @property
    def leader_id(self) -> str | None:
        """Find the active leader node ID across the cluster."""
        with self._lock:
            for node_id, log in self.nodes.items():
                if log.is_leader:
                    return node_id
            return None

    @property
    def leader(self) -> ReplicatedPartitionLog:
        """Return the active leader log instance, or raise if election in progress."""
        with self._lock:
            lid = self.leader_id
            if lid is None or lid not in self.nodes:
                raise RuntimeError(
                    "No active Raft leader in cluster (election required or partition isolated)"
                )
            return self.nodes[lid]

    @property
    def quorum_size(self) -> int:
        return (self.node_count // 2) + 1

    def propose_and_commit(
        self,
        cmd: CommandEnvelope,
    ) -> tuple[CommandReceipt, tuple[EventEnvelope, ...]]:
        """Propose a mutation to the active leader, replicating across quorum followers."""
        with self._lock:
            leader_log = self.leader
            follower_fsms = [fsm for nid, fsm in self.fsms.items() if nid != leader_log.node_id]
            return leader_log.propose_and_commit(cmd, follower_fsms=follower_fsms)

    def isolate_node(self, node_id: str) -> None:
        """Simulate a crash or network partition isolating a specific node."""
        with self._lock:
            self.transport.isolate_node(node_id)
            log = self.nodes.get(node_id)
            if log and log.is_leader:
                log.is_leader = False
                log.role = "FOLLOWER"

    def reconnect_node(self, node_id: str) -> None:
        """Restore network connectivity to an isolated node."""
        with self._lock:
            self.transport.reconnect_node(node_id)

    def trigger_election(self, candidate_id: str) -> bool:
        """Trigger a candidate node to start an election."""
        with self._lock:
            candidate = self.nodes.get(candidate_id)
            if candidate is None:
                raise KeyError(f"Node {candidate_id} not found")
            return candidate.start_election()

    def verify_state_consistency(self) -> bool:
        """Verify that all non-isolated nodes agree on canonical state hash (I11)."""
        with self._lock:
            hashes = {}
            for nid, fsm in self.fsms.items():
                if nid not in self.transport._partitions_isolated:
                    hashes[nid] = fsm.get_state_hash()
            if not hashes:
                return True
            unique_hashes = set(hashes.values())
            return len(unique_hashes) == 1

    def add_node(self, node_id: str) -> None:
        """Dynamically add a new node to the cluster under joint consensus Cold,new (Item 8)."""
        with self._lock:
            if node_id in self.nodes:
                return
            node_wal_dir = self.base_wal_dir / node_id
            node_wal_dir.mkdir(parents=True, exist_ok=True)
            fsm = PartitionFSM(self.partition_id)
            existing_peers = list(self.nodes.keys())
            log = ReplicatedPartitionLog(
                partition_id=self.partition_id,
                node_id=node_id,
                is_leader=False,
                peers=existing_peers,
                wal_dir=node_wal_dir,
                fsm=fsm,
                transport=self.transport,
            )
            # Update peers across all existing nodes
            for existing_log in self.nodes.values():
                if hasattr(existing_log, "peers") and node_id not in existing_log.peers:
                    if isinstance(existing_log.peers, list):
                        existing_log.peers.append(node_id)
            self.nodes[node_id] = log
            self.fsms[node_id] = fsm
            self.node_count = len(self.nodes)
            self.transport.register_node(node_id, self.partition_id, log)

    def remove_node(self, node_id: str) -> None:
        """Dynamically remove a node from the cluster under joint consensus (Item 8)."""
        with self._lock:
            if node_id not in self.nodes:
                return
            self.transport.isolate_node(node_id)
            self.nodes.pop(node_id, None)
            self.fsms.pop(node_id, None)
            for existing_log in self.nodes.values():
                if hasattr(existing_log, "peers") and isinstance(existing_log.peers, list):
                    if node_id in existing_log.peers:
                        existing_log.peers.remove(node_id)
            self.node_count = len(self.nodes)

    def close(self) -> None:
        """Clean up cluster resources and temporary storage."""
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
            self._temp_dir = None


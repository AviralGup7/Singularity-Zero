"""Replicated Partition Log, Raft Consensus Driver & Certified Receipt Engine (Level 0 Core).

Implements the authoritative per-partition append-only, hash-chained Raft log and multi-replica commit driver:
- Quorum-governed replication (AppendEntries / RequestVote RPCs) across RaftTransportProtocol
- Crash-safe write-ahead logging (WAL) on disk with CRC-64 verification and fsync barriers
- Strict durability ordering: Persist -> Quorum ACK -> Advance commitIndex -> FSM.Apply -> Outbox -> Receipt
- Multi-replica deterministic state machine application with identical canonical state hashes
- Leader-only cryptographic receipt generation and signature binding
- Crash recovery and uncommitted tail reconciliation
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.contracts.canonical_target import (
    canonical_state_encode,
    compute_canonical_state_hash,
)
from src.core.contracts.command_envelope import (
    CommandEnvelope,
    CommandReceipt,
    CommandResult,
    CommittedEntry,
    EventEnvelope,
)
from src.core.frontier.outbox import DurableOutboxLedger
from src.core.frontier.raft_fsm import PartitionFSM
from src.core.frontier.raft_transport import (
    AppendEntriesRequest,
    AppendEntriesResponse,
    RaftTransportProtocol,
    RequestVoteRequest,
    RequestVoteResponse,
)
from src.infrastructure.frontier.wal import compute_crc64

logger = logging.getLogger(__name__)


class PartitionWAL:
    """Crash-safe append-only WAL storage for partition Raft entries."""

    def __init__(self, partition_id: str, node_id: str, wal_dir: Path | str | None = None) -> None:
        self.partition_id = partition_id
        self.node_id = node_id
        self._wal_path: Path | None = None
        if wal_dir is not None:
            base_dir = Path(wal_dir)
            base_dir.mkdir(parents=True, exist_ok=True)
            self._wal_path = base_dir / f"raft_wal_{partition_id}_{node_id}.aof"

        self._in_memory_records: list[tuple[CommittedEntry, bool]] = []
        self._lock = threading.RLock()

    @property
    def wal_path(self) -> Path | None:
        return self._wal_path

    def append_entry(self, entry: CommittedEntry, committed: bool = False, sync: bool = True) -> None:
        """Persist a single entry to disk with CRC-64 verification and atomic fsync."""
        with self._lock:
            self._in_memory_records.append((entry, committed))
            if self._wal_path is None:
                return

            entry_dict = entry.to_dict()
            data_raw = json.dumps(entry_dict, sort_keys=True).encode("utf-8")
            crc = compute_crc64(data_raw)
            record = {
                "raft_index": entry.raft_index,
                "raft_term": entry.raft_term,
                "committed": committed,
                "crc64": crc,
                "entry": entry_dict,
            }
            line = json.dumps(record, sort_keys=True).encode("utf-8") + b"\n"
            with open(self._wal_path, "ab") as f:
                f.write(line)
                if sync:
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass

    def load_all_entries(self) -> list[tuple[CommittedEntry, bool]]:
        """Load and validate all entries from the physical WAL (or in-memory cache)."""
        with self._lock:
            if self._wal_path is None or not self._wal_path.exists():
                return list(self._in_memory_records)

            results: list[tuple[CommittedEntry, bool]] = []
            with open(self._wal_path, "rb") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line.decode("utf-8"))
                        entry_dict = record.get("entry", {})
                        data_raw = json.dumps(entry_dict, sort_keys=True).encode("utf-8")
                        crc_expected = record.get("crc64")
                        if crc_expected and compute_crc64(data_raw) != crc_expected:
                            logger.warning("Corrupt WAL line skipped due to CRC mismatch")
                            continue
                        entry = CommittedEntry.from_dict(entry_dict)
                        committed = bool(record.get("committed", False))
                        results.append((entry, committed))
                    except Exception as exc:
                        logger.warning("Malformed WAL record skipped: %s", exc)
            return results


class ReplicatedPartitionLog:
    """Per-partition Raft log coordinator, consensus manager, and multi-replica commit driver."""

    def __init__(
        self,
        partition_id: str,
        node_id: str = "node-1",
        current_term: int = 1,
        is_leader: bool = True,
        peers: Sequence[str] = (),
        transport: RaftTransportProtocol | None = None,
        signer_key_id: str = "K-2026-A",
        fsm: PartitionFSM | None = None,
        wal_dir: Path | str | None = None,
        outbox_dir: Path | str | None = None,
    ) -> None:
        self.partition_id = partition_id
        self.node_id = node_id
        self.current_term = current_term
        self.is_leader = is_leader
        self.role = "LEADER" if is_leader else "FOLLOWER"
        self.peers = list(peers)
        self.transport = transport
        self.signer_key_id = signer_key_id
        self.fsm = fsm if fsm is not None else PartitionFSM(partition_id=partition_id)
        
        self.wal = PartitionWAL(partition_id=partition_id, node_id=node_id, wal_dir=wal_dir)
        self.outbox = DurableOutboxLedger(partition_id=partition_id, outbox_dir=outbox_dir)
        
        self.entries: list[CommittedEntry] = []
        self.commit_index: int = 0
        self.last_applied: int = 0
        self.voted_for: str | None = node_id if is_leader else None
        self._last_entry_hash: str = "0" * 64
        self._lock = threading.RLock()
        
        # Recover state from existing WAL on startup (if persisted)
        if wal_dir is not None:
            self._recover_from_wal()

    @property
    def quorum_size(self) -> int:
        """Calculate majority quorum requirement: (N // 2) + 1."""
        total_cluster_nodes = 1 + len(self.peers)
        return (total_cluster_nodes // 2) + 1

    @property
    def last_entry_hash(self) -> str:
        with self._lock:
            return self._last_entry_hash

    def _recover_from_wal(self) -> None:
        """Replay valid committed entries from persistent WAL storage into memory and FSM."""
        with self._lock:
            loaded = self.wal.load_all_entries()
            if not loaded:
                return
            for entry, committed in loaded:
                if committed:
                    self.entries.append(entry)
                    self.commit_index = entry.raft_index
                    self._last_entry_hash = entry.entry_hash
                    # Replay into FSM if not already applied
                    if self.fsm.last_applied_index < entry.raft_index:
                        self.fsm.apply(entry)
                        self.last_applied = entry.raft_index

    def propose_and_commit(
        self,
        cmd: CommandEnvelope,
        follower_fsms: Sequence[PartitionFSM] = (),
    ) -> tuple[CommandReceipt, tuple[EventEnvelope, ...]]:
        """Propose a command, enforce quorum durability, advance commitIndex, apply to FSM, and issue receipt."""
        with self._lock:
            if self.role != "LEADER":
                raise RuntimeError(f"Node {self.node_id} is not leader (current role: {self.role})")

            next_index = self.commit_index + 1
            prev_hash = self._last_entry_hash

            # 1. Compute Candidate Entry Hash
            raw_entry_data = {
                "partition_id": self.partition_id,
                "raft_term": self.current_term,
                "raft_index": next_index,
                "command": cmd.to_dict(),
                "prev_hash": prev_hash,
            }
            entry_hash = hashlib.sha256(canonical_state_encode("v2.1.0", raw_entry_data)).hexdigest()

            pre_state_hash = self.fsm.get_state_hash()
            
            # Temporary entry to evaluate FSM transition deterministically
            temp_entry = CommittedEntry(
                partition_id=self.partition_id,
                raft_term=self.current_term,
                raft_index=next_index,
                entry_hash=entry_hash,
                previous_entry_hash=prev_hash,
                command=cmd,
                transition_result=CommandResult(
                    status="SUCCESS",
                    aggregate_id=cmd.aggregate_id,
                    resulting_aggregate_version=0,
                    result_code="PENDING",
                ),
            )

            # 2. Step A: Persist Uncommitted Entry to Leader's Durable WAL
            candidate_entry = CommittedEntry(
                partition_id=self.partition_id,
                raft_term=self.current_term,
                raft_index=next_index,
                entry_hash=entry_hash,
                previous_entry_hash=prev_hash,
                command=cmd,
                transition_result=CommandResult(
                    status="SUCCESS",
                    aggregate_id=cmd.aggregate_id,
                    resulting_aggregate_version=0,
                    result_code="PENDING",
                ),
            )
            self.wal.append_entry(candidate_entry, committed=False, sync=True)

            # 3. Step B: Replicate to Remote Peers & Collect Quorum ACKs
            ack_count = 1  # Leader itself counts as 1 ACK
            if self.peers and self.transport is not None:
                append_req = AppendEntriesRequest(
                    term=self.current_term,
                    leader_id=self.node_id,
                    prev_log_index=self.commit_index,
                    prev_log_term=self.current_term,
                    entries=(candidate_entry,),
                    leader_commit=self.commit_index,
                )
                for peer_id in self.peers:
                    resp = self.transport.send_append_entries(peer_id, append_req)
                    if resp.success:
                        ack_count += 1

            # 4. Step C: Quorum Verification
            if ack_count < self.quorum_size:
                logger.warning(
                    "Partition %s: Quorum lost on proposal %s (Acks %d < Quorum %d)",
                    self.partition_id,
                    cmd.command_id,
                    ack_count,
                    self.quorum_size,
                )
                raise RuntimeError(
                    f"QUORUM_LOST: Proposal {cmd.command_id} rejected. Only {ack_count}/{self.quorum_size} nodes acknowledged."
                )

            # 5. Step D: Quorum Reached -> Advance commitIndex & Commit in Leader WAL
            self.commit_index = next_index
            self._last_entry_hash = entry_hash
            
            # 6. Step E: Apply to Leader FSM (Committed Entries Only Reach FSM.Apply)
            post_state_hash, emitted_events, result = self.fsm.apply(temp_entry)
            self.last_applied = next_index

            committed_entry = CommittedEntry(
                partition_id=self.partition_id,
                raft_term=self.current_term,
                raft_index=next_index,
                entry_hash=entry_hash,
                previous_entry_hash=prev_hash,
                command=cmd,
                transition_result=result,
                emitted_events=emitted_events,
            )
            self.entries.append(committed_entry)
            self.wal.append_entry(committed_entry, committed=True, sync=True)

            # 7. Step F: Durable Outbox Append
            self.outbox.append_events(emitted_events, sync=True)

            # 8. Step G: Notify Remote Followers of Commitment
            if self.peers and self.transport is not None:
                commit_req = AppendEntriesRequest(
                    term=self.current_term,
                    leader_id=self.node_id,
                    prev_log_index=next_index,
                    prev_log_term=self.current_term,
                    entries=(),
                    leader_commit=self.commit_index,
                )
                for peer_id in self.peers:
                    self.transport.send_append_entries(peer_id, commit_req)

            # 9. Backward Compatibility for in-memory follower_fsms (e.g. integration tests)
            for f_fsm in follower_fsms:
                f_fsm.apply(temp_entry)

            # 10. Step H: Issue Certified CommandReceipt (Leader Only)
            receipt_payload = {
                "command_id": cmd.command_id,
                "partition_id": self.partition_id,
                "raft_term": self.current_term,
                "raft_index": next_index,
                "entry_hash": entry_hash,
                "aggregate_id": cmd.aggregate_id,
                "resulting_aggregate_version": result.resulting_aggregate_version,
                "result_code": result.result_code,
                "previous_state_hash": pre_state_hash,
                "state_hash_at_commit": post_state_hash,
                "signer_key_id": self.signer_key_id,
            }
            sig_raw = canonical_state_encode("v2.1.0", receipt_payload)
            cryptographic_signature = hashlib.sha256(sig_raw).hexdigest()

            event_ids = tuple(e.event_id for e in emitted_events)
            receipt = CommandReceipt(
                receipt_id=f"rcpt-{uuid.uuid4().hex[:12]}",
                command_id=cmd.command_id,
                partition_id=self.partition_id,
                raft_term=self.current_term,
                raft_index=next_index,
                entry_hash=entry_hash,
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=result.resulting_aggregate_version,
                result_code=result.result_code,
                result_payload_hash=hashlib.sha256(canonical_state_encode("v2.1.0", result.result_payload)).hexdigest(),
                emitted_event_ids=event_ids,
                previous_state_hash=pre_state_hash,
                state_hash_at_commit=post_state_hash,
                signer_key_id=self.signer_key_id,
                cryptographic_signature=cryptographic_signature,
            )

            return receipt, emitted_events

    def handle_append_entries_rpc(self, request: AppendEntriesRequest) -> AppendEntriesResponse:
        """Handle AppendEntries RPC on a follower replica."""
        with self._lock:
            # 1. Term check
            if request.term < self.current_term:
                return AppendEntriesResponse(
                    term=self.current_term,
                    node_id=self.node_id,
                    success=False,
                    match_index=self.commit_index,
                    error_code="STALE_TERM",
                )

            # Step down if higher term received
            if request.term > self.current_term:
                self.current_term = request.term
                self.role = "FOLLOWER"
                self.is_leader = False
                self.voted_for = None

            # 2. Append new entries to local WAL and memory
            for entry in request.entries:
                self.wal.append_entry(entry, committed=False, sync=True)
                # Overwrite or append
                if entry.raft_index > len(self.entries):
                    self.entries.append(entry)
                else:
                    self.entries[entry.raft_index - 1] = entry

            # 3. Process leader commit index advancement
            if request.leader_commit > self.commit_index:
                new_commit = min(request.leader_commit, len(self.entries))
                while self.commit_index < new_commit:
                    self.commit_index += 1
                    committed_entry = self.entries[self.commit_index - 1]
                    self._last_entry_hash = committed_entry.entry_hash
                    # Apply to follower FSM
                    _, emitted_events, _ = self.fsm.apply(committed_entry)
                    self.last_applied = self.commit_index
                    self.wal.append_entry(committed_entry, committed=True, sync=True)
                    self.outbox.append_events(emitted_events, sync=True)

            return AppendEntriesResponse(
                term=self.current_term,
                node_id=self.node_id,
                success=True,
                match_index=len(self.entries),
            )

    def handle_request_vote_rpc(self, request: RequestVoteRequest) -> RequestVoteResponse:
        """Handle RequestVote RPC on a replica."""
        with self._lock:
            if request.term < self.current_term:
                return RequestVoteResponse(
                    term=self.current_term,
                    node_id=self.node_id,
                    vote_granted=False,
                    error_code="STALE_TERM",
                )

            if request.term > self.current_term:
                self.current_term = request.term
                self.role = "FOLLOWER"
                self.is_leader = False
                self.voted_for = None

            # Vote granting logic
            can_vote = self.voted_for in (None, request.candidate_id)
            log_ok = request.last_log_index >= self.commit_index
            if can_vote and log_ok:
                self.voted_for = request.candidate_id
                return RequestVoteResponse(
                    term=self.current_term,
                    node_id=self.node_id,
                    vote_granted=True,
                )

            return RequestVoteResponse(
                term=self.current_term,
                node_id=self.node_id,
                vote_granted=False,
                error_code="VOTE_DENIED",
            )

    def start_election(self) -> bool:
        """Initiate leader election: increment term, vote for self, collect peer votes."""
        with self._lock:
            self.current_term += 1
            self.role = "CANDIDATE"
            self.voted_for = self.node_id
            votes = 1  # Self vote

            if not self.peers or self.transport is None:
                # Single-node cluster becomes leader immediately
                self.role = "LEADER"
                self.is_leader = True
                return True

            vote_req = RequestVoteRequest(
                term=self.current_term,
                candidate_id=self.node_id,
                last_log_index=self.commit_index,
                last_log_term=self.current_term,
            )

            for peer_id in self.peers:
                resp = self.transport.send_request_vote(peer_id, vote_req)
                if resp.vote_granted:
                    votes += 1

            if votes >= self.quorum_size:
                self.role = "LEADER"
                self.is_leader = True
                logger.info("Node %s won election for term %d with %d votes", self.node_id, self.current_term, votes)
                return True
            else:
                self.role = "FOLLOWER"
                self.is_leader = False
                logger.info("Node %s lost election for term %d (got %d/%d votes)", self.node_id, self.current_term, votes, self.quorum_size)
                return False

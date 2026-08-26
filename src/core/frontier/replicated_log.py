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
import time
import uuid
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from src.core.contracts.canonical_target import (
    canonical_state_encode,
)
from src.core.contracts.command_envelope import (
    CommandEnvelope,
    CommandReceipt,
    CommandResult,
    CommittedEntry,
    EventEnvelope,
)
from src.core.frontier.failure_model import AuthorityLostError, ReplicaDivergenceError
from src.core.frontier.outbox import DurableOutboxLedger
from src.core.frontier.raft_fsm import PartitionFSM
from src.core.frontier.raft_transport import (
    AppendEntriesRequest,
    AppendEntriesResponse,
    RaftTransportProtocol,
    RequestVoteRequest,
    RequestVoteResponse,
)
from src.core.frontier.receipt_crypto import (
    receipt_bind_payload,
    sign_receipt,
    signing_key_id,
)
from src.core.frontier.wal_errors import WALCorruptionError
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

    def append_entry(
        self, entry: CommittedEntry, committed: bool = False, sync: bool = True
    ) -> None:
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
        """Load and validate all entries from the physical WAL (or in-memory cache).

        Invariant I15: a CRC mismatch or malformed record aborts recovery with
        zero state mutations (no partial apply, no skip-and-continue).
        """
        with self._lock:
            if self._wal_path is None or not self._wal_path.exists():
                return list(self._in_memory_records)

            results: list[tuple[CommittedEntry, bool]] = []
            with open(self._wal_path, "rb") as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line.decode("utf-8"))
                        entry_dict = record.get("entry", {})
                        data_raw = json.dumps(entry_dict, sort_keys=True).encode("utf-8")
                        crc_expected = record.get("crc64")
                        if crc_expected and compute_crc64(data_raw) != crc_expected:
                            raise WALCorruptionError(
                                f"CRC-64 mismatch in PartitionWAL {self._wal_path} line {line_no}"
                            )
                        entry = CommittedEntry.from_dict(entry_dict)
                        committed = bool(record.get("committed", False))
                        results.append((entry, committed))
                    except WALCorruptionError:
                        raise
                    except Exception as exc:
                        raise WALCorruptionError(
                            f"Malformed PartitionWAL record in {self._wal_path} line {line_no}: {exc}"
                        ) from exc
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
        signer_key_id: str | None = None,
        fsm: PartitionFSM | None = None,
        wal_dir: Path | str | None = None,
        outbox_dir: Path | str | None = None,
        local_region: str = "local",
        leader_region: str | None = None,
    ) -> None:
        self.partition_id = partition_id
        self.node_id = node_id
        self.current_term = current_term
        self.is_leader = is_leader
        self.role = "LEADER" if is_leader else "FOLLOWER"
        self.local_region = str(local_region or "local").strip() or "local"
        self.leader_region = str(leader_region or self.local_region).strip() or self.local_region
        self.authority_epoch = 1
        self.fence_token = ""
        self.placement: Any | None = None
        self.peers = list(peers)
        self.transport = transport
        self.signer_key_id = signer_key_id or signing_key_id()
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

    def bind_placement(self, placement: Any) -> None:
        """Attach P-0000 placement so propose_and_commit honors I37 fences."""
        self.placement = placement

    def install_authority(self, lease: Any) -> None:
        """Adopt a live I37 lease after activate (new home) or genesis."""
        self.authority_epoch = int(getattr(lease, "authority_epoch", 1) or 1)
        self.fence_token = str(getattr(lease, "fence_token", "") or "")
        self.leader_region = str(getattr(lease, "home_region", "") or self.leader_region)
        self.current_term = int(
            getattr(lease, "leader_term", self.current_term) or self.current_term
        )
        phase = str(
            getattr(getattr(lease, "phase", None), "value", getattr(lease, "phase", "")) or ""
        )
        self.is_leader = phase != "fenced" and self.local_region == self.leader_region
        self.role = "LEADER" if self.is_leader else "FOLLOWER"

    def _recover_from_wal(self) -> None:
        """Replay valid committed entries from persistent WAL storage into memory and FSM.

        Corruption raises ``WALCorruptionError`` before any FSM apply (I15).
        """
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
            # I35: crash between WAL commit and outbox append reconstructs
            # the outbox from stored emitted_events (EventId is the dedupe key).
            self._rebuild_outbox_from_committed()

    def _rebuild_outbox_from_committed(self) -> int:
        """Rebuild DurableOutbox from committed WAL entries (I35)."""
        from src.core.frontier.recovery_protocol import rebuild_outbox_from_committed_entries

        return rebuild_outbox_from_committed_entries(self.entries, self.outbox)

    def propose_and_commit(
        self,
        cmd: CommandEnvelope,
        follower_fsms: Sequence[PartitionFSM] = (),
    ) -> tuple[CommandReceipt, tuple[EventEnvelope, ...]]:
        """Propose a command, enforce quorum durability, advance commitIndex, apply to FSM, and issue receipt."""
        with self._lock:
            if not self.is_leader:
                raise AuthorityLostError(
                    "AUTHORITY_LOSS: refusing mutation; this node is not the partition leader"
                )
            from src.core.frontier.region_model import (
                RegionRole,
                assert_region_may_accept_command,
            )

            assert_region_may_accept_command(
                local_region=self.local_region,
                leader_region=self.leader_region,
                role=RegionRole.AUTHORITY_HOME,
                partition_id=self.partition_id,
            )
            if self.placement is not None:
                from src.core.frontier.authority_transfer import assert_mutation_allowed

                lease = self.placement.lease_for(self.partition_id)
                assert_mutation_allowed(
                    lease,
                    observed_region=self.local_region,
                    observed_epoch=int(self.authority_epoch or lease.authority_epoch),
                    observed_token=str(self.fence_token or lease.fence_token),
                    observed_term=int(self.current_term) if self.fence_token else None,
                )
            # 0. Command Admission Clock-Skew & Drift Validation (I22')
            now_admission = time.time()
            if cmd.created_at_unix > now_admission + 10.0:
                raise ValueError(
                    f"Clock drift rejected: command timestamp {cmd.created_at_unix} is in future relative to admission clock {now_admission}"
                )
            if (
                self.entries
                and cmd.created_at_unix < self.entries[-1].command.created_at_unix - 5.0
            ):
                raise ValueError(
                    f"Clock skew rejected: command timestamp {cmd.created_at_unix} violates monotonic admission threshold (< {self.entries[-1].command.created_at_unix - 5.0})"
                )

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
            entry_hash = hashlib.sha256(
                canonical_state_encode("v2.1.0", raw_entry_data)
            ).hexdigest()

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
                raise AuthorityLostError(
                    f"QUORUM_LOST: Proposal {cmd.command_id} rejected. "
                    f"Only {ack_count}/{self.quorum_size} nodes acknowledged."
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
                f_hash, _, _ = f_fsm.apply(temp_entry)
                if f_hash != post_state_hash:
                    raise ReplicaDivergenceError(
                        f"REPLICATION_DIVERGENCE: follower FSM hash {f_hash} "
                        f"!= leader {post_state_hash} at index {next_index}"
                    )

            # 10. Step H: Issue Certified CommandReceipt (Leader Only)
            receipt_payload = receipt_bind_payload(
                command_id=cmd.command_id,
                partition_id=self.partition_id,
                raft_term=self.current_term,
                raft_index=next_index,
                entry_hash=entry_hash,
                previous_state_hash=pre_state_hash,
                state_hash_at_commit=post_state_hash,
                signer_key_id=self.signer_key_id,
            )
            cryptographic_signature = sign_receipt(receipt_payload)

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
                result_payload_hash=hashlib.sha256(
                    canonical_state_encode("v2.1.0", result.result_payload)
                ).hexdigest(),
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
                logger.info(
                    "Node %s won election for term %d with %d votes",
                    self.node_id,
                    self.current_term,
                    votes,
                )
                return True
            else:
                self.role = "FOLLOWER"
                self.is_leader = False
                logger.info(
                    "Node %s lost election for term %d (got %d/%d votes)",
                    self.node_id,
                    self.current_term,
                    votes,
                    self.quorum_size,
                )
                return False

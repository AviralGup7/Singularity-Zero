"""Deterministic Partition Finite State Machine (Level 1 FSM Core).

Implements the pure deterministic state transition engine for partitioned Raft groups (Axiom 1, 2, 3):
- Replicas apply committed entries identically with zero external side effects
- Pure transition execution without reading wall clocks, RNG, or external networks
- Monotonic aggregate versioning incremented on mutating transitions only
- Authoritative idempotency index recording deterministic CommandResults
- Canonical state encoding and deterministic state hash computation
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from src.core.contracts.canonical_target import (
    canonical_state_encode,
    compute_canonical_state_hash,
)
from src.core.contracts.command_envelope import (
    CommandEnvelope,
    CommandResult,
    CommittedEntry,
    EventEnvelope,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SubLeaseRecord:
    """Authoritative sub-lease record tracking allocation and consumption on partition."""

    sublease_id: str
    run_id: str
    partition_id: str
    units_allocated: int
    units_consumed: int
    status: str  # "ISSUED", "ACTIVE", "SETTLEMENT_PENDING", "CLOSED", "EXPIRED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sublease_id": self.sublease_id,
            "run_id": self.run_id,
            "partition_id": self.partition_id,
            "units_allocated": self.units_allocated,
            "units_consumed": self.units_consumed,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SubLeaseRecord:
        return cls(
            sublease_id=str(data.get("sublease_id", "")),
            run_id=str(data.get("run_id", "")),
            partition_id=str(data.get("partition_id", "P-0000")),
            units_allocated=int(data.get("units_allocated", 0)),
            units_consumed=int(data.get("units_consumed", 0)),
            status=str(data.get("status", "ACTIVE")),
        )


@dataclass(frozen=True, slots=True)
class AggregateState:
    """State of an individual aggregate root inside Level 1 FSM."""

    aggregate_id: str
    aggregate_type: str
    version: int
    state_payload: Mapping[str, Any]
    status: str = "ACTIVE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregate_id": self.aggregate_id,
            "aggregate_type": self.aggregate_type,
            "version": self.version,
            "state_payload": dict(self.state_payload),
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class CertifiedSnapshot:
    """Certified Raft snapshot for state machine compaction and fast recovery (Axiom 5, Contract Section 7)."""

    partition_id: str
    last_included_index: int
    last_included_term: int
    schema_version: str
    state_hash: str
    state_payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "last_included_index": self.last_included_index,
            "last_included_term": self.last_included_term,
            "schema_version": self.schema_version,
            "state_hash": self.state_hash,
            "state_payload": dict(self.state_payload),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CertifiedSnapshot:
        return cls(
            partition_id=str(data.get("partition_id", "P-0000")),
            last_included_index=int(data.get("last_included_index", 0)),
            last_included_term=int(data.get("last_included_term", 0)),
            schema_version=str(data.get("schema_version", "v2.1.0")),
            state_hash=str(data.get("state_hash", "")),
            state_payload=dict(data.get("state_payload", {})),
        )


class PartitionFSM:
    """Pure deterministic single-writer state machine running on every Raft replica."""

    def __init__(self, partition_id: str, schema_version: str = "v2.1.0") -> None:
        self.partition_id = partition_id
        self.schema_version = schema_version
        self.last_applied_index: int = 0
        self.last_applied_term: int = 0
        self.aggregates: dict[str, AggregateState] = {}
        self.idempotency_index: dict[str, CommandResult] = {}
        self.revocation_registry: set[str] = set()
        self.subleases: dict[str, SubLeaseRecord] = {}
        self.key_revocation_epoch: int = 0
        self._current_state_hash: str = compute_canonical_state_hash(self.schema_version, self.to_dict())

    def get_state_hash(self) -> str:
        """Return the current deterministic canonical state hash."""
        return self._current_state_hash

    def export_certified_snapshot(self) -> CertifiedSnapshot:
        """Export an immutable, certified snapshot at current applied index."""
        current_state_dict = self.to_dict()
        state_hash = compute_canonical_state_hash(self.schema_version, current_state_dict)
        return CertifiedSnapshot(
            partition_id=self.partition_id,
            last_included_index=self.last_applied_index,
            last_included_term=self.last_applied_term,
            schema_version=self.schema_version,
            state_hash=state_hash,
            state_payload=current_state_dict,
        )

    def load_certified_snapshot(self, snapshot: CertifiedSnapshot) -> bool:
        """Restore FSM state from a certified snapshot after verifying canonical state hash (Invariant I12)."""
        expected_hash = compute_canonical_state_hash(snapshot.schema_version, snapshot.state_payload)
        if expected_hash != snapshot.state_hash:
            raise ValueError(f"Snapshot integrity violation (I12): expected {expected_hash} != {snapshot.state_hash}")

        payload = snapshot.state_payload
        self.partition_id = str(payload.get("partition_id", self.partition_id))
        self.last_applied_index = int(payload.get("last_applied_index", 0))
        self.last_applied_term = int(payload.get("last_applied_term", 0))
        self.key_revocation_epoch = int(payload.get("key_revocation_epoch", 0))

        self.aggregates = {
            k: AggregateState(
                aggregate_id=v["aggregate_id"],
                aggregate_type=v["aggregate_type"],
                version=v["version"],
                state_payload=v["state_payload"],
                status=v.get("status", "ACTIVE"),
            )
            for k, v in payload.get("aggregates", {}).items()
        }
        self.idempotency_index = {
            k: CommandResult.from_dict(v)
            for k, v in payload.get("idempotency_index", {}).items()
        }
        self.revocation_registry = set(payload.get("revocation_registry", []))
        self.subleases = {
            k: SubLeaseRecord.from_dict(v)
            for k, v in payload.get("subleases", {}).items()
        }
        self._current_state_hash = compute_canonical_state_hash(self.schema_version, self.to_dict())
        return True

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete FSM state to a dictionary for canonical encoding."""
        return {
            "partition_id": self.partition_id,
            "last_applied_index": self.last_applied_index,
            "last_applied_term": self.last_applied_term,
            "key_revocation_epoch": self.key_revocation_epoch,
            "aggregates": {k: v.to_dict() for k, v in self.aggregates.items()},
            "idempotency_index": {k: v.to_dict() for k, v in self.idempotency_index.items()},
            "revocation_registry": sorted(list(self.revocation_registry)),
            "subleases": {k: v.to_dict() for k, v in self.subleases.items()},
        }

    def apply(self, entry: CommittedEntry) -> tuple[str, tuple[EventEnvelope, ...], CommandResult]:
        """Pure deterministic state transition execution on committed log entry.

        Returns (new_state_hash, emitted_events, command_result).
        """
        cmd = entry.command
        cmd_id = cmd.command_id
        agg_id = cmd.aggregate_id

        # 1. Idempotency Check (Axiom 6)
        if cmd_id in self.idempotency_index:
            cached_result = self.idempotency_index[cmd_id]
            logger.debug("PartitionFSM[%s]: Idempotent command %s returning cached result", self.partition_id, cmd_id)
            return self._current_state_hash, (), cached_result

        # Update applied coordinates
        self.last_applied_index = entry.raft_index
        self.last_applied_term = entry.raft_term

        # 2. Command Dispatch & Pure Evaluation
        result, events = self._execute_transition(cmd, entry.raft_term, entry.raft_index)

        # 3. Record in Idempotency Index
        self.idempotency_index[cmd_id] = result

        # 4. Recompute Canonical State Hash
        self._current_state_hash = compute_canonical_state_hash(self.schema_version, self.to_dict())
        return self._current_state_hash, events, result

    def _execute_transition(
        self,
        cmd: CommandEnvelope,
        raft_term: int,
        raft_index: int,
    ) -> tuple[CommandResult, tuple[EventEnvelope, ...]]:
        cmd_type = cmd.command_type
        agg_id = cmd.aggregate_id
        current_agg = self.aggregates.get(agg_id)
        current_version = current_agg.version if current_agg else 0

        # Optimistic concurrency check
        if cmd.expected_aggregate_version is not None and cmd.expected_aggregate_version != current_version:
            result = CommandResult(
                status="REJECTED",
                aggregate_id=agg_id,
                resulting_aggregate_version=current_version,
                result_code="VERSION_CONFLICT",
                error_message=f"Expected version {cmd.expected_aggregate_version} != current {current_version}",
            )
            return result, ()

        # Transition dispatch table
        if cmd_type == "AuthorizeExecutionCommand":
            return self._handle_authorize_execution(cmd, current_version, raft_term, raft_index)
        elif cmd_type == "SubmitExecutionClaim":
            return self._handle_submit_claim(cmd, current_version, raft_term, raft_index)
        elif cmd_type == "CancelExecutionCommand":
            return self._handle_cancel_execution(cmd, current_version, raft_term, raft_index)
        elif cmd_type == "LeaseTimeoutCommand":
            return self._handle_lease_timeout(cmd, current_version, raft_term, raft_index)
        elif cmd_type == "AllocateSubLeaseCommand":
            return self._handle_allocate_sublease(cmd, current_version, raft_term, raft_index)
        elif cmd_type == "SyncKeyRevocationCommand":
            return self._handle_sync_key_revocation(cmd, current_version, raft_term, raft_index)
        else:
            result = CommandResult(
                status="REJECTED",
                aggregate_id=agg_id,
                resulting_aggregate_version=current_version,
                result_code="UNKNOWN_COMMAND_TYPE",
                error_message=f"Unrecognized command type: {cmd_type}",
            )
            return result, ()

    def _handle_authorize_execution(
        self,
        cmd: CommandEnvelope,
        current_version: int,
        raft_term: int,
        raft_index: int,
    ) -> tuple[CommandResult, tuple[EventEnvelope, ...]]:
        payload = cmd.payload
        cap_id = str(payload.get("capability_id", ""))
        sublease_id = str(payload.get("sublease_id", ""))
        requested_units = int(payload.get("units_requested", 1))

        # Check key revocation
        key_epoch = int(payload.get("key_epoch", 0))
        if key_epoch < self.key_revocation_epoch:
            return CommandResult(
                status="REJECTED",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="KEY_REVOKED",
                error_message="Capability signed by revoked key epoch",
            ), ()

        # Check sub-lease balance
        sublease = self.subleases.get(sublease_id)
        if not sublease or (sublease.units_consumed + requested_units > sublease.units_allocated):
            return CommandResult(
                status="REJECTED",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="INSUFFICIENT_SUBLEASE_BALANCE",
                error_message="Sub-lease allocation exhausted",
            ), ()

        # Mutating transition
        new_version = current_version + 1
        self.aggregates[cmd.aggregate_id] = AggregateState(
            aggregate_id=cmd.aggregate_id,
            aggregate_type="ExecutionAggregate",
            version=new_version,
            state_payload={
                "capability_id": cap_id,
                "sublease_id": sublease_id,
                "units_reserved": requested_units,
                "status": "RUNNING",
            },
            status="RUNNING",
        )

        evt_id = EventEnvelope.derive_event_id(self.partition_id, raft_index, 0)
        event = EventEnvelope(
            event_id=evt_id,
            event_type="ExecutionAuthorizedEvent",
            aggregate_id=cmd.aggregate_id,
            aggregate_version=new_version,
            payload={
                "capability_id": cap_id,
                "sublease_id": sublease_id,
                "units_reserved": requested_units,
            },
            correlation_id=cmd.correlation_id,
            causation_id=cmd.causation_id,
            partition_id=self.partition_id,
            raft_term=raft_term,
            raft_index=raft_index,
        )

        return CommandResult(
            status="SUCCESS",
            aggregate_id=cmd.aggregate_id,
            resulting_aggregate_version=new_version,
            result_code="EXECUTION_AUTHORIZED",
            result_payload={"capability_id": cap_id, "new_version": new_version},
        ), (event,)

    def _handle_submit_claim(
        self,
        cmd: CommandEnvelope,
        current_version: int,
        raft_term: int,
        raft_index: int,
    ) -> tuple[CommandResult, tuple[EventEnvelope, ...]]:
        agg = self.aggregates.get(cmd.aggregate_id)
        if not agg or agg.status != "RUNNING":
            return CommandResult(
                status="REJECTED",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="EXECUTION_NOT_RUNNING",
                error_message=f"Execution in status {agg.status if agg else 'NOT_FOUND'}",
            ), ()

        payload = cmd.payload
        cap_id = str(payload.get("capability_id", ""))
        if cap_id in self.revocation_registry:
            return CommandResult(
                status="REJECTED",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="CAPABILITY_REVOKED",
                error_message="Execution capability is revoked",
            ), ()

        consumed_units = int(payload.get("units_consumed", 1))
        reserved_units = int(agg.state_payload.get("units_reserved", 1))
        sublease_id = str(agg.state_payload.get("sublease_id", ""))

        # Update local sublease ledger
        if sublease_id in self.subleases:
            curr_sub = self.subleases[sublease_id]
            new_consumed = curr_sub.units_consumed + min(consumed_units, reserved_units)
            self.subleases[sublease_id] = SubLeaseRecord(
                sublease_id=curr_sub.sublease_id,
                run_id=curr_sub.run_id,
                partition_id=curr_sub.partition_id,
                units_allocated=curr_sub.units_allocated,
                units_consumed=new_consumed,
                status="SETTLEMENT_PENDING",
            )

        new_version = current_version + 1
        unused_delta = max(0, reserved_units - consumed_units)
        self.aggregates[cmd.aggregate_id] = AggregateState(
            aggregate_id=cmd.aggregate_id,
            aggregate_type="ExecutionAggregate",
            version=new_version,
            state_payload={
                "status": "SETTLED",
                "units_consumed": consumed_units,
                "unused_refund": unused_delta,
                "findings": payload.get("findings", []),
            },
            status="SETTLED",
        )

        evt_id = EventEnvelope.derive_event_id(self.partition_id, raft_index, 0)
        event = EventEnvelope(
            event_id=evt_id,
            event_type="ExecutionClaimSettledEvent",
            aggregate_id=cmd.aggregate_id,
            aggregate_version=new_version,
            payload={
                "units_consumed": consumed_units,
                "unused_refund": unused_delta,
                "sublease_id": sublease_id,
                "findings_count": len(payload.get("findings", [])),
            },
            correlation_id=cmd.correlation_id,
            causation_id=cmd.causation_id,
            partition_id=self.partition_id,
            raft_term=raft_term,
            raft_index=raft_index,
        )

        return CommandResult(
            status="SUCCESS",
            aggregate_id=cmd.aggregate_id,
            resulting_aggregate_version=new_version,
            result_code="CLAIM_SETTLED_SUCCESS",
            result_payload={"units_consumed": consumed_units, "refund_units": unused_delta},
        ), (event,)

    def _handle_cancel_execution(
        self,
        cmd: CommandEnvelope,
        current_version: int,
        raft_term: int,
        raft_index: int,
    ) -> tuple[CommandResult, tuple[EventEnvelope, ...]]:
        agg = self.aggregates.get(cmd.aggregate_id)
        if not agg:
            return CommandResult(
                status="REJECTED",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="AGGREGATE_NOT_FOUND",
            ), ()

        if agg.status == "SETTLED":
            return CommandResult(
                status="NO_OP",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="ALREADY_SETTLED",
            ), ()

        if agg.status == "CANCELLED":
            return CommandResult(
                status="NO_OP",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="ALREADY_CANCELLED",
            ), ()

        cap_id = str(agg.state_payload.get("capability_id", ""))
        if cap_id:
            self.revocation_registry.add(cap_id)

        reserved_units = int(agg.state_payload.get("units_reserved", 0))
        sublease_id = str(agg.state_payload.get("sublease_id", ""))

        new_version = current_version + 1
        self.aggregates[cmd.aggregate_id] = AggregateState(
            aggregate_id=cmd.aggregate_id,
            aggregate_type="ExecutionAggregate",
            version=new_version,
            state_payload={"status": "CANCELLED", "refund_units": reserved_units},
            status="CANCELLED",
        )

        evt_id = EventEnvelope.derive_event_id(self.partition_id, raft_index, 0)
        event = EventEnvelope(
            event_id=evt_id,
            event_type="ExecutionCancelledEvent",
            aggregate_id=cmd.aggregate_id,
            aggregate_version=new_version,
            payload={
                "capability_id": cap_id,
                "sublease_id": sublease_id,
                "refund_units": reserved_units,
            },
            correlation_id=cmd.correlation_id,
            causation_id=cmd.causation_id,
            partition_id=self.partition_id,
            raft_term=raft_term,
            raft_index=raft_index,
        )

        return CommandResult(
            status="SUCCESS",
            aggregate_id=cmd.aggregate_id,
            resulting_aggregate_version=new_version,
            result_code="EXECUTION_CANCELLED_SUCCESS",
            result_payload={"refund_units": reserved_units},
        ), (event,)

    def _handle_lease_timeout(
        self,
        cmd: CommandEnvelope,
        current_version: int,
        raft_term: int,
        raft_index: int,
    ) -> tuple[CommandResult, tuple[EventEnvelope, ...]]:
        agg = self.aggregates.get(cmd.aggregate_id)
        if not agg or agg.status != "RUNNING":
            return CommandResult(
                status="NO_OP",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="EXECUTION_NOT_RUNNING",
            ), ()

        observed_at = float(cmd.payload.get("observed_at", 0.0))
        expires_at = float(agg.state_payload.get("expires_at", 0.0))
        max_skew = float(cmd.payload.get("max_skew", 0.5))

        if expires_at > 0.0 and observed_at < (expires_at + max_skew):
            return CommandResult(
                status="REJECTED",
                aggregate_id=cmd.aggregate_id,
                resulting_aggregate_version=current_version,
                result_code="NOT_YET_EXPIRED",
            ), ()

        # Pessimistic Lease Reconciliation (Axiom 4)
        reserved_units = int(agg.state_payload.get("units_reserved", 1))
        sublease_id = str(agg.state_payload.get("sublease_id", ""))

        new_version = current_version + 1
        self.aggregates[cmd.aggregate_id] = AggregateState(
            aggregate_id=cmd.aggregate_id,
            aggregate_type="ExecutionAggregate",
            version=new_version,
            state_payload={"status": "EXPIRED", "consumed": reserved_units, "refund": 0},
            status="EXPIRED",
        )

        evt_id = EventEnvelope.derive_event_id(self.partition_id, raft_index, 0)
        event = EventEnvelope(
            event_id=evt_id,
            event_type="LeaseExpiredEvent",
            aggregate_id=cmd.aggregate_id,
            aggregate_version=new_version,
            payload={
                "sublease_id": sublease_id,
                "consumed_forfeit": reserved_units,
                "refund": 0,
            },
            correlation_id=cmd.correlation_id,
            causation_id=cmd.causation_id,
            partition_id=self.partition_id,
            raft_term=raft_term,
            raft_index=raft_index,
        )

        return CommandResult(
            status="SUCCESS",
            aggregate_id=cmd.aggregate_id,
            resulting_aggregate_version=new_version,
            result_code="LEASE_EXPIRED_PESSIMISTIC",
            result_payload={"forfeited_units": reserved_units},
        ), (event,)

    def _handle_allocate_sublease(
        self,
        cmd: CommandEnvelope,
        current_version: int,
        raft_term: int,
        raft_index: int,
    ) -> tuple[CommandResult, tuple[EventEnvelope, ...]]:
        payload = cmd.payload
        sublease_id = str(payload.get("sublease_id", ""))
        run_id = str(payload.get("run_id", ""))
        allocated_units = int(payload.get("units_allocated", 0))

        self.subleases[sublease_id] = SubLeaseRecord(
            sublease_id=sublease_id,
            run_id=run_id,
            partition_id=self.partition_id,
            units_allocated=allocated_units,
            units_consumed=0,
            status="ACTIVE",
        )

        new_version = current_version + 1
        evt_id = EventEnvelope.derive_event_id(self.partition_id, raft_index, 0)
        event = EventEnvelope(
            event_id=evt_id,
            event_type="SubLeaseAllocatedEvent",
            aggregate_id=sublease_id,
            aggregate_version=new_version,
            payload={"units_allocated": allocated_units, "run_id": run_id},
            correlation_id=cmd.correlation_id,
            causation_id=cmd.causation_id,
            partition_id=self.partition_id,
            raft_term=raft_term,
            raft_index=raft_index,
        )

        return CommandResult(
            status="SUCCESS",
            aggregate_id=sublease_id,
            resulting_aggregate_version=new_version,
            result_code="SUBLEASE_ALLOCATED",
            result_payload={"units_allocated": allocated_units},
        ), (event,)

    def _handle_sync_key_revocation(
        self,
        cmd: CommandEnvelope,
        current_version: int,
        raft_term: int,
        raft_index: int,
    ) -> tuple[CommandResult, tuple[EventEnvelope, ...]]:
        new_epoch = int(cmd.payload.get("revocation_epoch", 0))
        if new_epoch > self.key_revocation_epoch:
            self.key_revocation_epoch = new_epoch

        new_version = current_version + 1
        evt_id = EventEnvelope.derive_event_id(self.partition_id, raft_index, 0)
        event = EventEnvelope(
            event_id=evt_id,
            event_type="KeyRevocationSyncedEvent",
            aggregate_id=cmd.aggregate_id,
            aggregate_version=new_version,
            payload={"revocation_epoch": new_epoch},
            correlation_id=cmd.correlation_id,
            causation_id=cmd.causation_id,
            partition_id=self.partition_id,
            raft_term=raft_term,
            raft_index=raft_index,
        )

        return CommandResult(
            status="SUCCESS",
            aggregate_id=cmd.aggregate_id,
            resulting_aggregate_version=new_version,
            result_code="KEY_REVOCATION_SYNCED",
            result_payload={"new_revocation_epoch": new_epoch},
        ), (event,)

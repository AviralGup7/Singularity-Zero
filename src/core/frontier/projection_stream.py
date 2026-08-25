"""Projection Vector Watermarks, Committed Log Consumer & Cold Rebuild Engine (Level 3 Plane).

Implements the deterministic Level 3 projection plane (Contract Section 8 & 10):
- Vectorized partition watermark tracking: (partition_id, term, last_applied_index, event_hash)
- Gap & corruption detection (K > last + 1 -> GAP_DETECTED; hash mismatch -> CORRUPTED_LOG)
- Parallel cold rebuild protocol from committed logs offset 0
- Idempotent at-least-once projection consumption
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from src.core.contracts.canonical_target import (
    canonical_state_encode,
    compute_canonical_state_hash,
)
from src.core.contracts.command_envelope import CommittedEntry, EventEnvelope
from src.core.frontier.replicated_log import ReplicatedPartitionLog

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PartitionCheckpoint:
    """Individual partition progress within a projection checkpoint vector."""

    partition_id: str
    term: int
    last_applied_index: int
    last_event_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "term": self.term,
            "last_applied_index": self.last_applied_index,
            "last_event_hash": self.last_event_hash,
        }


@dataclass(frozen=True, slots=True)
class ProjectionCheckpointVector:
    """Multi-partition watermark vector for a Level 3 projection."""

    projection_id: str
    schema_version: str = "v2.1.0"
    placement_version: int = 7
    partition_offsets: dict[str, PartitionCheckpoint] = field(default_factory=dict)
    state_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "projection_id": self.projection_id,
            "schema_version": self.schema_version,
            "placement_version": self.placement_version,
            "partition_offsets": {k: v.to_dict() for k, v in self.partition_offsets.items()},
            "state_hash": self.state_hash,
        }


class CommittedLogConsumer:
    """Idempotent consumer streaming committed entries to build materialized read models."""

    def __init__(self, projection_id: str, schema_version: str = "v2.1.0") -> None:
        self.projection_id = projection_id
        self.schema_version = schema_version
        self.materialized_view: dict[str, Any] = {}
        self.partition_offsets: dict[str, PartitionCheckpoint] = {}

    def get_checkpoint_vector(self) -> ProjectionCheckpointVector:
        state_hash = compute_canonical_state_hash(self.schema_version, self.materialized_view)
        return ProjectionCheckpointVector(
            projection_id=self.projection_id,
            schema_version=self.schema_version,
            partition_offsets=dict(self.partition_offsets),
            state_hash=state_hash,
        )

    def consume_entry(self, entry: CommittedEntry) -> tuple[bool, str]:
        """Consume a committed log entry with strict gap and corruption detection."""
        part_id = entry.partition_id
        curr_ckpt = self.partition_offsets.get(
            part_id,
            PartitionCheckpoint(part_id, entry.raft_term, 0, "0" * 64),
        )

        incoming_index = entry.raft_index

        # 1. Historical Duplicate Check (K < last_applied)
        if incoming_index < curr_ckpt.last_applied_index:
            return True, "HISTORICAL_DUPLICATE_ACKNOWLEDGED"

        # 2. Same Duplicate Check (K == last_applied)
        if incoming_index == curr_ckpt.last_applied_index:
            if entry.entry_hash != curr_ckpt.last_event_hash:
                raise ValueError(f"Corruption detected at index {incoming_index}: entry hash mismatch")
            return True, "SAME_DUPLICATE_ACKNOWLEDGED"

        # 3. Gap Detection (K > last_applied + 1)
        if incoming_index > curr_ckpt.last_applied_index + 1:
            raise ValueError(
                f"GAP_DETECTED on {part_id}: received index {incoming_index} but last applied is {curr_ckpt.last_applied_index}"
            )

        # 4. Hash-Chain Link Check
        if curr_ckpt.last_applied_index > 0 and entry.previous_entry_hash != curr_ckpt.last_event_hash:
            raise ValueError(
                f"CORRUPTED_LOG on {part_id} at {incoming_index}: prev_hash {entry.previous_entry_hash} != {curr_ckpt.last_event_hash}"
            )

        # 5. Apply Events to Materialized View
        for evt in entry.emitted_events:
            self._apply_event_to_view(evt)

        # 6. Advance Checkpoint Vector
        self.partition_offsets[part_id] = PartitionCheckpoint(
            partition_id=part_id,
            term=entry.raft_term,
            last_applied_index=incoming_index,
            last_event_hash=entry.entry_hash,
        )
        return True, "APPLIED_SUCCESSFULLY"

    def _apply_event_to_view(self, event: EventEnvelope) -> None:
        """Update in-memory materialized read view idempotently."""
        evt_type = event.event_type
        agg_id = event.aggregate_id
        payload = event.payload

        if evt_type == "ExecutionAuthorizedEvent":
            self.materialized_view[agg_id] = {
                "status": "RUNNING",
                "capability_id": payload.get("capability_id"),
                "units_reserved": payload.get("units_reserved", 1),
            }
        elif evt_type == "ExecutionClaimSettledEvent":
            entry = self.materialized_view.setdefault(agg_id, {})
            entry["status"] = "SETTLED"
            entry["units_consumed"] = payload.get("units_consumed", 1)
            entry["findings_count"] = payload.get("findings_count", 0)
        elif evt_type == "ExecutionCancelledEvent":
            entry = self.materialized_view.setdefault(agg_id, {})
            entry["status"] = "CANCELLED"
            entry["refund_units"] = payload.get("refund_units", 0)
        elif evt_type == "LeaseExpiredEvent":
            entry = self.materialized_view.setdefault(agg_id, {})
            entry["status"] = "EXPIRED"

    def cold_rebuild(self, partition_logs: Mapping[str, ReplicatedPartitionLog]) -> str:
        """Deterministic cold rebuild protocol from offset 0 across all partition logs."""
        self.materialized_view.clear()
        self.partition_offsets.clear()

        # Replay all committed entries sequentially per partition
        for part_id, p_log in sorted(partition_logs.items()):
            for entry in p_log.entries:
                self.consume_entry(entry)

        return compute_canonical_state_hash(self.schema_version, self.materialized_view)

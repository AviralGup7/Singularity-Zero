"""Global Coordination Authority (Partition P-0000 Level 1 Aggregates).

Implements the central coordination authority for the Cyber Security Test Pipeline (Contract Section 4 & 5):
- GlobalBudgetAggregate enforcing exact integer conservation: Total = Consumed + Outstanding + Available
- GlobalRunAggregate managing authoritative multi-partition scan lifecycle
- PlacementAuthority managing 1024 virtual partitions and 5-stage fenced migration
- GlobalControlAggregate managing cluster key revocation epochs
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from src.core.contracts.command_envelope import (
    CommandEnvelope,
)
from src.core.frontier.failure_model import BudgetInconsistencyError
from src.core.frontier.lease_status import (
    LeaseStatus,
    is_outstanding,
    normalize_lease_status,
    require_transition,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class GlobalSubLease:
    """Sub-lease tracked on Global Budget Authority P-0000."""

    sublease_id: str
    run_id: str
    partition_id: str
    units_allocated: int
    status: str = LeaseStatus.RESERVED.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "sublease_id": self.sublease_id,
            "run_id": self.run_id,
            "partition_id": self.partition_id,
            "units_allocated": self.units_allocated,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class QuotaSlab:
    """Multi-Raft budget slab allocated by P-0000 to a partition leader (Invariant I26)."""

    slab_id: str
    partition_id: str
    allocated_units: int
    consumed_units: int = 0
    status: str = "ALLOCATED"  # "ALLOCATED", "EXHAUSTED", "RECLAIMED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "slab_id": self.slab_id,
            "partition_id": self.partition_id,
            "allocated_units": self.allocated_units,
            "consumed_units": self.consumed_units,
            "status": self.status,
        }


class GlobalBudgetAggregate:
    """Enforces Universal Budget Conservation and Multi-Raft Quota Slabs (Axiom 4, Invariants I5, I26)."""

    def __init__(self, total_budget: int = 10000) -> None:
        self.total_budget: int = int(total_budget)
        self.consumed: int = 0
        self.available: int = int(total_budget)
        self.subleases: dict[str, GlobalSubLease] = {}
        self.quota_slabs: dict[str, QuotaSlab] = {}
        self.version: int = 1

    @property
    def outstanding_reserved(self) -> int:
        sublease_res = sum(
            sl.units_allocated for sl in self.subleases.values() if is_outstanding(sl.status)
        )
        slab_res = sum(
            slab.allocated_units - slab.consumed_units
            for slab in self.quota_slabs.values()
            if slab.status == "ALLOCATED"
        )
        return sublease_res + slab_res

    def verify_conservation(self) -> bool:
        """Verify universal budget conservation equation: Total = Consumed + Outstanding + Available."""
        return self.total_budget == (self.consumed + self.outstanding_reserved + self.available)

    def require_conservation(self) -> None:
        """I5/I34: fail-closed if the conservation equation does not hold.

        Callers must not retry or roll back the log. Outstanding RESERVED/EXPIRED
        subleases may be compensated (I28).
        """
        if self.verify_conservation():
            return
        raise BudgetInconsistencyError(
            "BUDGET_INCONSISTENCY: "
            f"Total={self.total_budget} Consumed={self.consumed} "
            f"Outstanding={self.outstanding_reserved} Available={self.available}"
        )

    def allocate_quota_slab(
        self,
        slab_id: str,
        partition_id: str,
        units: int,
    ) -> tuple[bool, str]:
        """Atomically allocate a budget quota slab to a partition leader (I26)."""
        if units <= 0:
            return False, "Slab units must be strictly positive"
        if units > self.available:
            return (
                False,
                f"Insufficient available budget: requested {units} > available {self.available}",
            )

        self.available -= units
        self.quota_slabs[slab_id] = QuotaSlab(
            slab_id=slab_id,
            partition_id=partition_id,
            allocated_units=units,
            consumed_units=0,
            status="ALLOCATED",
        )
        self.version += 1
        self.require_conservation()
        return True, "QUOTA_SLAB_ALLOCATED"

    def reclaim_quota_slab(
        self,
        slab_id: str,
        consumed_units: int = 0,
    ) -> tuple[bool, str]:
        """Reclaim remaining unconsumed quota from a slab back into available budget (I26)."""
        slab = self.quota_slabs.get(slab_id)
        if not slab:
            return False, f"Quota slab {slab_id} not found"
        if slab.status != "ALLOCATED":
            return False, f"Quota slab {slab_id} is already {slab.status}"

        consumed = max(slab.consumed_units, consumed_units)
        if consumed > slab.allocated_units:
            return False, f"Consumed units {consumed} exceeds slab allocated {slab.allocated_units}"

        unconsumed = slab.allocated_units - consumed
        self.consumed += consumed
        self.available += unconsumed
        self.quota_slabs[slab_id] = QuotaSlab(
            slab_id=slab.slab_id,
            partition_id=slab.partition_id,
            allocated_units=slab.allocated_units,
            consumed_units=consumed,
            status="RECLAIMED",
        )
        self.version += 1
        self.require_conservation()
        return True, "QUOTA_SLAB_RECLAIMED"

    def reserve_sublease(
        self,
        sublease_id: str,
        run_id: str,
        partition_id: str,
        units: int,
    ) -> tuple[bool, str]:
        """Atomically reserve units from available into an outstanding sub-lease."""
        if units > self.available:
            return (
                False,
                f"Insufficient available budget: requested {units} > available {self.available}",
            )

        self.available -= units
        self.subleases[sublease_id] = GlobalSubLease(
            sublease_id=sublease_id,
            run_id=run_id,
            partition_id=partition_id,
            units_allocated=units,
            status=LeaseStatus.RESERVED.value,
        )
        self.version += 1
        self.require_conservation()
        return True, "SUBLEASE_RESERVED"

    def settle_return(
        self,
        sublease_id: str,
        units_consumed: int,
        units_returned: int,
    ) -> tuple[bool, str]:
        """Reconcile sub-lease consumption and return unconsumed units to available."""
        sublease = self.subleases.get(sublease_id)
        if not sublease:
            return False, f"Sublease {sublease_id} not found"

        current = normalize_lease_status(sublease.status)
        if current is LeaseStatus.CONSUMED:
            return (
                False,
                f"Sublease {sublease_id} is already consumed (duplicate settlement rejected)",
            )
        if current is LeaseStatus.COMPENSATED:
            return True, f"Sublease {sublease_id} already in terminal state {current.value}"

        if units_consumed < 0 or units_returned < 0:
            return False, "Negative units not allowed in budget settlement"

        if units_consumed + units_returned != sublease.units_allocated:
            return False, (
                f"Budget conservation invariant violated: units_consumed ({units_consumed}) + "
                f"units_returned ({units_returned}) != units_allocated ({sublease.units_allocated})"
            )

        target = LeaseStatus.COMPENSATED if units_consumed == 0 else LeaseStatus.CONSUMED
        try:
            require_transition(current, target)
        except ValueError as exc:
            return False, str(exc)

        self.consumed += units_consumed
        self.available += units_returned
        self.subleases[sublease_id] = GlobalSubLease(
            sublease_id=sublease.sublease_id,
            run_id=sublease.run_id,
            partition_id=sublease.partition_id,
            units_allocated=sublease.units_allocated,
            status=target.value,
        )
        self.version += 1
        self.require_conservation()
        return True, f"SUBLEASE_{target.value}"

    def expire_sublease(
        self,
        sublease_id: str,
        units_consumed: int = 0,
    ) -> tuple[bool, str]:
        """Expire an outstanding sub-lease and return unconsumed units to available (INVARIANT-005)."""
        sublease = self.subleases.get(sublease_id)
        if not sublease:
            return False, f"Sublease {sublease_id} not found"

        current = normalize_lease_status(sublease.status)
        try:
            require_transition(current, LeaseStatus.EXPIRED)
        except ValueError as exc:
            return False, str(exc)
        if current is LeaseStatus.EXPIRED:
            return False, f"Sublease {sublease_id} is already EXPIRED"

        if units_consumed < 0 or units_consumed > sublease.units_allocated:
            return False, f"Invalid units_consumed: {units_consumed}"

        units_returned = sublease.units_allocated - units_consumed
        self.consumed += units_consumed
        self.available += units_returned
        self.subleases[sublease_id] = GlobalSubLease(
            sublease_id=sublease.sublease_id,
            run_id=sublease.run_id,
            partition_id=sublease.partition_id,
            units_allocated=sublease.units_allocated,
            status=LeaseStatus.EXPIRED.value,
        )
        self.version += 1
        return True, "SUBLEASE_EXPIRED_AND_RECLAIMED"

    def apply_command(self, envelope: CommandEnvelope) -> tuple[bool, str]:
        """Apply a typed P-0000 budget command. Version fence is optional."""
        if (
            envelope.expected_aggregate_version is not None
            and envelope.expected_aggregate_version != self.version
        ):
            return False, "VERSION_CONFLICT"
        cmd_type = envelope.command_type
        payload = envelope.payload
        if cmd_type == "ReserveGlobalBudgetCommand":
            return self.reserve_sublease(
                sublease_id=str(payload.get("sublease_id") or f"sl_{envelope.command_id}"),
                run_id=str(payload.get("run_id", "")),
                partition_id=str(payload.get("partition_id", "P-0000")),
                units=int(payload.get("units", 0)),
            )
        if cmd_type == "SettlementReturnCommand":
            return self.settle_return(
                sublease_id=str(payload.get("sublease_id", "")),
                units_consumed=int(payload.get("units_consumed", 0)),
                units_returned=int(payload.get("units_returned", 0)),
            )
        if cmd_type == "ExpireSubLeaseCommand":
            return self.expire_sublease(
                sublease_id=str(payload.get("sublease_id") or envelope.aggregate_id),
                units_consumed=int(payload.get("units_consumed", 0)),
            )
        return False, f"UNKNOWN_COMMAND_TYPE:{cmd_type}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_budget": self.total_budget,
            "consumed": self.consumed,
            "outstanding_reserved": self.outstanding_reserved,
            "available": self.available,
            "version": self.version,
            "subleases": {k: v.to_dict() for k, v in self.subleases.items()},
        }


class GlobalRunAggregate:
    """Authoritative multi-partition Run state root on P-0000."""

    def __init__(self, run_id: str, target_partitions: tuple[str, ...] = ()) -> None:
        self.run_id = run_id
        self.target_partitions = target_partitions
        self.status = (
            "CREATED"  # CREATED, RESERVING, DISPATCHED, RUNNING, RECONCILING, COMPLETED, CANCELLED
        )
        self.partition_statuses: dict[str, str] = {p: "PENDING" for p in target_partitions}
        self.total_consumed: int = 0
        self.total_refunded: int = 0
        self.version: int = 1

    def transition_to_running(self) -> None:
        self.status = "RUNNING"
        self.version += 1

    def record_partition_completion(self, partition_id: str, consumed: int, refunded: int) -> None:
        self.partition_statuses[partition_id] = "COMPLETED"
        self.total_consumed += consumed
        self.total_refunded += refunded
        self.version += 1
        if all(
            st in ("COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT")
            for st in self.partition_statuses.values()
        ):
            self.status = "COMPLETED"

    def record_cancellation(self) -> None:
        self.status = "CANCELLED"
        self.version += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "target_partitions": list(self.target_partitions),
            "partition_statuses": dict(self.partition_statuses),
            "total_consumed": self.total_consumed,
            "total_refunded": self.total_refunded,
            "version": self.version,
        }


class PlacementAuthority:
    """Authoritative partition topology and 5-stage fenced migration manager on P-0000."""

    def __init__(self, initial_version: int = 7) -> None:
        self.placement_version = initial_version
        self.ownership_epochs: dict[str, int] = {}  # aggregate_id -> epoch
        self.migration_states: dict[str, str] = {}  # aggregate_id -> status

    def get_partition_for_target(self, target_identity_hash: str) -> str:
        """Deterministic virtual partition placement (1024 fixed virtual partitions)."""
        idx = int(target_identity_hash[:8], 16) % 1024
        return f"P-{idx:04d}"

    def initiate_transfer(self, aggregate_id: str, from_partition: str, to_partition: str) -> int:
        """Stage 1: P-0000 TransferIntentCommitted."""
        current_epoch = self.ownership_epochs.get(aggregate_id, 1)
        new_epoch = current_epoch + 1
        self.ownership_epochs[aggregate_id] = new_epoch
        self.migration_states[aggregate_id] = (
            f"TRANSFER_PREPARED:{from_partition}->{to_partition}:{new_epoch}"
        )
        self.placement_version += 1
        return new_epoch

    def activate_ownership(self, aggregate_id: str, new_owner_partition: str, epoch: int) -> bool:
        """Stage 4: P-0000 OwnershipActivated."""
        if self.ownership_epochs.get(aggregate_id) != epoch:
            return False
        self.migration_states[aggregate_id] = f"OWNED_BY:{new_owner_partition}:{epoch}"
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "placement_version": self.placement_version,
            "ownership_epochs": dict(self.ownership_epochs),
            "migration_states": dict(self.migration_states),
        }

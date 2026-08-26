"""Durable Cross-Partition Run Saga Engine (Level 1/0 Orchestrator).

Implements cross-partition workflow management without distributed transactions (Axiom 8, Contract Section 4):
- Decomposes multi-partition targets under placement_version
- Requests dynamic sub-leases from GlobalBudgetAggregate on P-0000
- Dispatches execution commands to partition Raft leaders
- Asynchronously reconciles settlement returns back to P-0000 Available budget
"""

from __future__ import annotations

import logging
import uuid

from src.core.contracts.command_envelope import CommandEnvelope
from src.core.frontier.global_coordination import (
    GlobalBudgetAggregate,
    GlobalRunAggregate,
    PlacementAuthority,
)
from src.core.frontier.lease_status import LeaseStatus, is_terminal, normalize_lease_status
from src.core.frontier.replicated_log import ReplicatedPartitionLog

logger = logging.getLogger(__name__)


class DurableRunSagaEngine:
    """Orchestrates cross-partition scan workflows through durable, idempotent saga steps."""

    def __init__(
        self,
        global_budget: GlobalBudgetAggregate,
        placement_authority: PlacementAuthority,
        partition_logs: dict[str, ReplicatedPartitionLog],
    ) -> None:
        self.global_budget = global_budget
        self.placement_authority = placement_authority
        self.partition_logs = partition_logs
        self.active_runs: dict[str, GlobalRunAggregate] = {}

    def start_scan_run(
        self,
        run_id: str,
        target_hashes: list[str],
        units_per_partition: int = 100,
    ) -> tuple[bool, str]:
        """Initiate multi-partition Run decomposition and sub-lease allocation."""
        # 1. Determine Target Partitions
        partition_map: dict[str, list[str]] = {}
        for th in target_hashes:
            part_id = self.placement_authority.get_partition_for_target(th)
            partition_map.setdefault(part_id, []).append(th)

        target_partitions = tuple(sorted(partition_map.keys()))
        run_agg = GlobalRunAggregate(run_id=run_id, target_partitions=target_partitions)
        self.active_runs[run_id] = run_agg

        # 2. Reserve Sub-Leases on Global Budget Authority P-0000
        for part_id in target_partitions:
            sublease_id = f"sublease_{run_id}_{part_id}"
            success, msg = self.global_budget.reserve_sublease(
                sublease_id=sublease_id,
                run_id=run_id,
                partition_id=part_id,
                units=units_per_partition,
            )
            if not success:
                run_agg.record_cancellation()
                return False, f"Global budget reservation failed: {msg}"

            # Dispatch AllocateSubLeaseCommand to partition log if registered
            if part_id in self.partition_logs:
                p_log = self.partition_logs[part_id]
                cmd = CommandEnvelope(
                    command_id=f"cmd_alloc_{uuid.uuid4().hex[:8]}",
                    command_type="AllocateSubLeaseCommand",
                    aggregate_id=sublease_id,
                    payload={
                        "sublease_id": sublease_id,
                        "run_id": run_id,
                        "units_allocated": units_per_partition,
                    },
                    correlation_id=run_id,
                    causation_id=f"saga_start_{run_id}",
                )
                p_log.propose_and_commit(cmd)

        run_agg.transition_to_running()
        return True, f"Run {run_id} started across {len(target_partitions)} partitions"

    def compensate_sublease(
        self,
        run_id: str,
        partition_id: str,
        sublease_id: str,
    ) -> tuple[bool, str]:
        """Compensate an unconsumed or aborted sub-lease allocation (Invariant I28).

        Enforces that COMPENSATED is only valid from RESERVED or EXPIRED states.
        Duplicate compensation calls are idempotent no-ops.
        """
        sublease = self.global_budget.subleases.get(sublease_id)
        if not sublease:
            return False, f"Sublease {sublease_id} not found"

        current = normalize_lease_status(sublease.status)
        if is_terminal(current):
            return True, f"Sublease {sublease_id} already in terminal state {current.value}"

        if current not in {LeaseStatus.RESERVED, LeaseStatus.EXPIRED}:
            return (
                False,
                f"Illegal lease transition (I28): cannot compensate from status {current.value}",
            )

        # Reclaim all allocated units to available budget
        success, msg = self.global_budget.settle_return(
            sublease_id=sublease_id,
            units_consumed=0,
            units_returned=sublease.units_allocated,
        )
        if not success:
            return False, f"Budget compensation failed: {msg}"

        if run_id in self.active_runs:
            run_agg = self.active_runs[run_id]
            run_agg.record_partition_completion(
                partition_id, consumed=0, refunded=sublease.units_allocated
            )

        return True, "SUBLEASE_COMPENSATED_SUCCESS"

    def handle_partition_settlement_return(
        self,
        run_id: str,
        partition_id: str,
        sublease_id: str,
        units_consumed: int,
        units_returned: int,
    ) -> bool:
        """Asynchronously reconcile settlement return back to P-0000 Global Budget (Invariant I28)."""
        sublease = self.global_budget.subleases.get(sublease_id)
        if sublease and is_terminal(sublease.status):
            return True

        success, msg = self.global_budget.settle_return(
            sublease_id=sublease_id,
            units_consumed=units_consumed,
            units_returned=units_returned,
        )
        if not success:
            logger.error("Failed to settle sub-lease return on P-0000: %s", msg)
            return False

        if run_id in self.active_runs:
            run_agg = self.active_runs[run_id]
            run_agg.record_partition_completion(partition_id, units_consumed, units_returned)

        return True

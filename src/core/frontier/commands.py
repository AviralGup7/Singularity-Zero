"""Typed formal commands that serialize to CommandEnvelope.

PartitionFSM still dispatches on ``command_type`` strings. These classes are
the canonical constructors so callers do not hand-build payload dicts.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from src.core.contracts.command_envelope import CommandEnvelope

COMMAND_TYPES: tuple[str, ...] = (
    "ReserveGlobalBudgetCommand",
    "AllocateSubLeaseCommand",
    "AuthorizeExecutionCommand",
    "ConsumeExecutionTicketCommand",
    "SubmitExecutionClaim",
    "CancelExecutionCommand",
    "SettlementReturnCommand",
    "LeaseTimeoutCommand",
    "ExpireSubLeaseCommand",
    "SyncKeyRevocationCommand",
    "RotateAuthorityKeyCommand",
    "PromotePolicyCommand",
    "RollbackPolicyCommand",
)


def _cid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True, slots=True)
class TypedCommand:
    command_type: str
    aggregate_id: str
    payload: Mapping[str, Any]
    command_id: str = ""
    correlation_id: str = ""
    causation_id: str = ""
    expected_aggregate_version: int | None = None
    schema_version: int = 1
    created_at_unix: float = field(default_factory=time.time)

    def to_envelope(self) -> CommandEnvelope:
        return CommandEnvelope(
            command_id=self.command_id or _cid("cmd"),
            command_type=self.command_type,
            aggregate_id=self.aggregate_id,
            payload=dict(self.payload),
            correlation_id=self.correlation_id or self.command_id or _cid("corr"),
            causation_id=self.causation_id or "",
            expected_aggregate_version=self.expected_aggregate_version,
            created_at_unix=self.created_at_unix,
            schema_version=self.schema_version,
        )

    @classmethod
    def from_envelope(cls, env: CommandEnvelope) -> TypedCommand:
        return cls(
            command_type=env.command_type,
            aggregate_id=env.aggregate_id,
            payload=dict(env.payload),
            command_id=env.command_id,
            correlation_id=env.correlation_id,
            causation_id=env.causation_id,
            expected_aggregate_version=env.expected_aggregate_version,
            schema_version=env.schema_version,
            created_at_unix=env.created_at_unix,
        )


def reserve_global_budget(
    *,
    run_id: str,
    partition_id: str,
    units: int,
    sublease_id: str = "",
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    sid = sublease_id or f"sublease_{run_id}_{partition_id}"
    return TypedCommand(
        command_type="ReserveGlobalBudgetCommand",
        aggregate_id="global_budget",
        payload={
            "run_id": run_id,
            "partition_id": partition_id,
            "units": int(units),
            "sublease_id": sid,
        },
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def allocate_sublease(
    *,
    sublease_id: str,
    run_id: str,
    units_allocated: int,
    partition_id: str = "",
    command_id: str = "",
) -> TypedCommand:
    payload: dict[str, Any] = {
        "sublease_id": sublease_id,
        "run_id": run_id,
        "units_allocated": int(units_allocated),
    }
    if partition_id:
        payload["partition_id"] = partition_id
    return TypedCommand(
        command_type="AllocateSubLeaseCommand",
        aggregate_id=sublease_id,
        payload=payload,
        command_id=command_id,
    )


def settlement_return(
    *,
    sublease_id: str,
    units_consumed: int,
    units_returned: int,
    command_id: str = "",
) -> TypedCommand:
    return TypedCommand(
        command_type="SettlementReturnCommand",
        aggregate_id="global_budget",
        payload={
            "sublease_id": sublease_id,
            "units_consumed": int(units_consumed),
            "units_returned": int(units_returned),
        },
        command_id=command_id,
    )


def promote_policy(
    *,
    policy_id: str,
    artifact_hash: str,
    policy_version: str,
    parent_policy_id: str = "",
    generation: int | None = None,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    payload: dict[str, Any] = {
        "policy_id": policy_id,
        "artifact_hash": artifact_hash,
        "policy_version": policy_version,
        "parent_policy_id": parent_policy_id,
    }
    if generation is not None:
        payload["generation"] = int(generation)
    return TypedCommand(
        command_type="PromotePolicyCommand",
        aggregate_id="policy_active",
        payload=payload,
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def rollback_policy(
    *,
    parent_policy_id: str,
    target_generation: int | None = None,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    payload: dict[str, Any] = {"parent_policy_id": parent_policy_id}
    if target_generation is not None:
        payload["target_generation"] = int(target_generation)
    return TypedCommand(
        command_type="RollbackPolicyCommand",
        aggregate_id="policy_active",
        payload=payload,
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def authorize_execution(
    *,
    aggregate_id: str,
    capability_id: str,
    sublease_id: str,
    units_requested: int = 1,
    key_epoch: int = 0,
    expires_at: float = 0.0,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    return TypedCommand(
        command_type="AuthorizeExecutionCommand",
        aggregate_id=aggregate_id,
        payload={
            "capability_id": capability_id,
            "sublease_id": sublease_id,
            "units_requested": int(units_requested),
            "key_epoch": int(key_epoch),
            "expires_at": float(expires_at),
        },
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def submit_execution_claim(
    *,
    aggregate_id: str,
    capability_id: str,
    units_consumed: int,
    findings: list[dict[str, Any]] | None = None,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    return TypedCommand(
        command_type="SubmitExecutionClaim",
        aggregate_id=aggregate_id,
        payload={
            "capability_id": capability_id,
            "units_consumed": int(units_consumed),
            "findings": list(findings or []),
        },
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def lease_timeout(
    *,
    aggregate_id: str,
    observed_at: float,
    max_skew: float = 0.5,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    return TypedCommand(
        command_type="LeaseTimeoutCommand",
        aggregate_id=aggregate_id,
        payload={
            "observed_at": float(observed_at),
            "max_skew": float(max_skew),
        },
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def expire_sublease(
    *,
    sublease_id: str,
    units_consumed: int = 0,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    return TypedCommand(
        command_type="ExpireSubLeaseCommand",
        aggregate_id="global_budget",
        payload={
            "sublease_id": sublease_id,
            "units_consumed": int(units_consumed),
        },
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def cancel_execution(
    *,
    aggregate_id: str,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    return TypedCommand(
        command_type="CancelExecutionCommand",
        aggregate_id=aggregate_id,
        payload={},
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def sync_key_revocation(
    *,
    aggregate_id: str = "key_revocation",
    revocation_epoch: int = 0,
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    return TypedCommand(
        command_type="SyncKeyRevocationCommand",
        aggregate_id=aggregate_id,
        payload={"revocation_epoch": int(revocation_epoch)},
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )


def make_rotate_authority_key_command(
    *,
    command_id: str = "",
    new_key_id: str,
    key_material_b64: str = "",
    aggregate_id: str = "authority_keys",
) -> TypedCommand:
    """Raft/operator ceremony: rotate AuthorityKeyRing active generation (I13)."""
    return TypedCommand(
        command_type="RotateAuthorityKeyCommand",
        aggregate_id=aggregate_id,
        payload={
            "new_key_id": new_key_id,
            "key_material_b64": key_material_b64,
        },
        command_id=command_id,
    )


def consume_execution_ticket(
    *,
    ticket_id: str,
    aggregate_id: str = "execution_tickets",
    run_id: str = "",
    command_id: str = "",
    expected_aggregate_version: int | None = None,
) -> TypedCommand:
    """Multi-host ticket consume intent (P0-4 target).

    Authoritative CAS consume must go through PartitionWAL / Raft so hosts
    share one consumed set. Process-local JSONL remains the durability floor
    when this command is not yet applied by the FSM.
    """
    tid = str(ticket_id or "").strip()
    if not tid:
        raise ValueError("ticket_id required")
    return TypedCommand(
        command_type="ConsumeExecutionTicketCommand",
        aggregate_id=aggregate_id,
        payload={
            "ticket_id": tid,
            "run_id": str(run_id or ""),
        },
        command_id=command_id,
        expected_aggregate_version=expected_aggregate_version,
    )

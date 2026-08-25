"""I34 — declared recovery semantics for classified failures.

F-018 used to answer only "what exit code?". This module answers
"what is the system allowed to do?" for each failure class:

    Retry / Rollback / Compensate / Fail-closed / Operator action

The table is the contract. Call sites consult it; they must not invent
a recovery action the table forbids. Exotic multi-node repair is out of
scope — the architecture still has to name the outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

I34_FAILURE_RECOVERY = "I34"


class FailureClass(StrEnum):
    WAL_CORRUPTION = "wal_corruption"
    AUTHORITY_LOSS = "authority_loss"
    REPLICATION_DIVERGENCE = "replication_divergence"
    EVENT_DELIVERY_FAILURE = "event_delivery_failure"
    BUDGET_INCONSISTENCY = "budget_inconsistency"
    FSM_INVARIANT_VIOLATION = "fsm_invariant_violation"


@dataclass(frozen=True, slots=True)
class RecoverySemantics:
    """What the system may do when this class of failure is observed."""

    failure_class: FailureClass
    retry: bool
    rollback: bool
    compensate: bool
    fail_closed: bool
    operator_action: str
    invariant: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_class": self.failure_class.value,
            "retry": self.retry,
            "rollback": self.rollback,
            "compensate": self.compensate,
            "fail_closed": self.fail_closed,
            "operator_action": self.operator_action,
            "invariant": self.invariant,
            "notes": self.notes,
        }

    def allows(self, action: str) -> bool:
        flag = {
            "retry": self.retry,
            "rollback": self.rollback,
            "compensate": self.compensate,
            "fail_closed": self.fail_closed,
        }.get(action)
        if flag is None:
            raise KeyError(f"unknown recovery action {action!r}")
        return flag


RECOVERY_TABLE: dict[FailureClass, RecoverySemantics] = {
    FailureClass.WAL_CORRUPTION: RecoverySemantics(
        failure_class=FailureClass.WAL_CORRUPTION,
        retry=False,
        rollback=False,
        compensate=False,
        fail_closed=True,
        operator_action=(
            "Restore a certified snapshot, or discard the corrupt uncommitted tail "
            "after verifying PartitionWAL CRC. Do not skip-and-continue."
        ),
        invariant="I15",
        notes="Corrupt records are never applied, so there is nothing to roll back or compensate.",
    ),
    FailureClass.AUTHORITY_LOSS: RecoverySemantics(
        failure_class=FailureClass.AUTHORITY_LOSS,
        retry=False,
        rollback=False,
        compensate=False,
        fail_closed=True,
        operator_action=(
            "Refuse new mutations until a leader exists. Single-node quorum-1: restart "
            "the process so start_election() self-elects. Do not panic-compensate leases."
        ),
        invariant="I17",
        notes="Outstanding RESERVED/ACTIVE subleases expire or compensate via I28, not on step-down.",
    ),
    FailureClass.REPLICATION_DIVERGENCE: RecoverySemantics(
        failure_class=FailureClass.REPLICATION_DIVERGENCE,
        retry=False,
        rollback=False,
        compensate=False,
        fail_closed=True,
        operator_action=(
            "Halt apply on the divergent replica. Restore FSM from leader PartitionWAL "
            "plus sequential replay (I16). Live CLI is quorum-1 so this is a test/cluster path."
        ),
        invariant="I11",
        notes="State hashes must match after applying the same committed entry.",
    ),
    FailureClass.EVENT_DELIVERY_FAILURE: RecoverySemantics(
        failure_class=FailureClass.EVENT_DELIVERY_FAILURE,
        retry=True,
        rollback=False,
        compensate=False,
        fail_closed=False,
        operator_action=(
            "None required. Outbox keeps EventId; DeliveryId is not recorded on failure, "
            "so dispatch replay is a no-op for already-delivered ids (I32/I33)."
        ),
        invariant="I32",
        notes="EventBus is not authority. Settlement stays COMMITTED.",
    ),
    FailureClass.BUDGET_INCONSISTENCY: RecoverySemantics(
        failure_class=FailureClass.BUDGET_INCONSISTENCY,
        retry=False,
        rollback=False,
        compensate=True,
        fail_closed=True,
        operator_action=(
            "Stop new reservations. Compensate outstanding RESERVED/EXPIRED subleases "
            "(I28). Do not invent budget units."
        ),
        invariant="I5",
        notes="Compensation is the legal return of Outstanding to Available; it is not a WAL rollback.",
    ),
    FailureClass.FSM_INVARIANT_VIOLATION: RecoverySemantics(
        failure_class=FailureClass.FSM_INVARIANT_VIOLATION,
        retry=False,
        rollback=False,
        compensate=False,
        fail_closed=True,
        operator_action=(
            "Stop FSM.Apply. Restore from certified snapshot plus sequential WAL replay (I16). "
            "Do not patch in-memory FSM state."
        ),
        invariant="I9/I16",
        notes="A violated invariant means the replica is no longer a source of truth.",
    ),
}


class ClassifiedFailure(Exception):
    """Exception that carries an I34 failure class."""

    failure_class: FailureClass

    @property
    def recovery(self) -> RecoverySemantics:
        return semantics_for(self.failure_class)


class AuthorityLostError(ClassifiedFailure, RuntimeError):
    """This node cannot mutate authoritative state (not leader / quorum lost)."""

    failure_class = FailureClass.AUTHORITY_LOSS


class ReplicaDivergenceError(ClassifiedFailure, RuntimeError):
    """Replica state hashes diverged after applying the same committed entry."""

    failure_class = FailureClass.REPLICATION_DIVERGENCE


class BudgetInconsistencyError(ClassifiedFailure, RuntimeError):
    """Global budget conservation equation does not hold."""

    failure_class = FailureClass.BUDGET_INCONSISTENCY


class FsmInvariantError(ClassifiedFailure, RuntimeError):
    """A formal FSM / log invariant failed the checker."""

    failure_class = FailureClass.FSM_INVARIANT_VIOLATION


def semantics_for(failure: FailureClass | str) -> RecoverySemantics:
    key = FailureClass(failure)
    return RECOVERY_TABLE[key]


def semantics_for_exception(exc: BaseException) -> RecoverySemantics | None:
    """Map a raised error onto the recovery table, if classified."""
    from src.core.frontier.wal_errors import WALCorruptionError

    if isinstance(exc, WALCorruptionError):
        return semantics_for(FailureClass.WAL_CORRUPTION)
    failure_class = getattr(exc, "failure_class", None)
    if isinstance(failure_class, FailureClass):
        return semantics_for(failure_class)
    return None


def must_not(failure: FailureClass, action: str) -> None:
    """Raise if a caller is about to perform a forbidden recovery action."""
    sem = semantics_for(failure)
    if sem.allows(action):
        return
    raise PermissionError(
        f"{I34_FAILURE_RECOVERY}: {failure.value} forbids {action} "
        f"(retry={sem.retry} rollback={sem.rollback} compensate={sem.compensate} "
        f"fail_closed={sem.fail_closed})"
    )


def recovery_matrix() -> tuple[dict[str, Any], ...]:
    """Stable row order for tests and docs."""
    return tuple(RECOVERY_TABLE[cls].to_dict() for cls in FailureClass)


__all__ = [
    "AuthorityLostError",
    "BudgetInconsistencyError",
    "ClassifiedFailure",
    "FailureClass",
    "FsmInvariantError",
    "I34_FAILURE_RECOVERY",
    "RECOVERY_TABLE",
    "RecoverySemantics",
    "ReplicaDivergenceError",
    "must_not",
    "recovery_matrix",
    "semantics_for",
    "semantics_for_exception",
]

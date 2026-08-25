"""I34 failure recovery model: declared semantics, not just exit codes."""

from __future__ import annotations

import pytest

from src.core.contracts.command_envelope import CommandEnvelope
from src.core.frontier.failure_model import (
    AuthorityLostError,
    BudgetInconsistencyError,
    FailureClass,
    FsmInvariantError,
    ReplicaDivergenceError,
    must_not,
    recovery_matrix,
    semantics_for,
    semantics_for_exception,
)
from src.core.frontier.global_coordination import GlobalBudgetAggregate
from src.core.frontier.invariant_checker import InvariantAuditReport, InvariantChecker
from src.core.frontier.replicated_log import ReplicatedPartitionLog
from src.core.frontier.wal_errors import WALCorruptionError


def test_i34_matrix_covers_every_class_and_forbids_the_wrong_actions() -> None:
    rows = {row["failure_class"]: row for row in recovery_matrix()}
    assert set(rows) == {cls.value for cls in FailureClass}

    wal = rows["wal_corruption"]
    assert wal["retry"] is False
    assert wal["rollback"] is False
    assert wal["compensate"] is False
    assert wal["fail_closed"] is True

    auth = rows["authority_loss"]
    assert auth["retry"] is False
    assert auth["fail_closed"] is True
    assert auth["compensate"] is False

    div = rows["replication_divergence"]
    assert div["retry"] is False
    assert div["fail_closed"] is True

    bus = rows["event_delivery_failure"]
    assert bus["retry"] is True
    assert bus["rollback"] is False
    assert bus["compensate"] is False
    assert bus["fail_closed"] is False

    budget = rows["budget_inconsistency"]
    assert budget["retry"] is False
    assert budget["rollback"] is False
    assert budget["compensate"] is True
    assert budget["fail_closed"] is True

    fsm = rows["fsm_invariant_violation"]
    assert fsm["retry"] is False
    assert fsm["fail_closed"] is True
    assert fsm["compensate"] is False


def test_i34_must_not_blocks_forbidden_actions() -> None:
    must_not(FailureClass.EVENT_DELIVERY_FAILURE, "rollback")
    must_not(FailureClass.EVENT_DELIVERY_FAILURE, "compensate")
    must_not(FailureClass.WAL_CORRUPTION, "retry")
    with pytest.raises(PermissionError, match="I34"):
        must_not(FailureClass.EVENT_DELIVERY_FAILURE, "retry")
    with pytest.raises(PermissionError, match="I34"):
        must_not(FailureClass.BUDGET_INCONSISTENCY, "compensate")


def test_i34_wal_corruption_is_fail_closed_no_compensate() -> None:
    exc = WALCorruptionError("CRC-64 mismatch")
    sem = semantics_for_exception(exc)
    assert sem is not None
    assert sem.failure_class is FailureClass.WAL_CORRUPTION
    assert sem.fail_closed is True
    assert sem.compensate is False
    assert sem.retry is False


def test_i34_follower_must_not_mutate() -> None:
    log = ReplicatedPartitionLog(partition_id="P-0001", node_id="n2", is_leader=False)
    cmd = CommandEnvelope(
        command_id="cmd_follower",
        command_type="AllocateSubLeaseCommand",
        aggregate_id="sl",
        payload={"sublease_id": "sl", "units_allocated": 1, "run_id": "R"},
        correlation_id="c",
        causation_id="x",
    )
    with pytest.raises(AuthorityLostError, match="AUTHORITY_LOSS"):
        log.propose_and_commit(cmd)
    assert log.commit_index == 0


def test_i34_budget_inconsistency_fail_closed_allows_compensate() -> None:
    budget = GlobalBudgetAggregate(total_budget=10)
    budget.available = 0
    with pytest.raises(BudgetInconsistencyError, match="BUDGET_INCONSISTENCY"):
        budget.require_conservation()
    sem = semantics_for(FailureClass.BUDGET_INCONSISTENCY)
    assert sem.compensate is True
    assert sem.retry is False
    assert sem.fail_closed is True


def test_i34_fsm_enforce_fail_closed() -> None:
    report = InvariantAuditReport(
        passed=False,
        passed_invariants=(),
        failed_invariants=(("I1_P-0000", "chain broken"),),
    )
    with pytest.raises(FsmInvariantError, match="FSM_INVARIANT_VIOLATION"):
        InvariantChecker.enforce(report)
    InvariantChecker.enforce(
        InvariantAuditReport(passed=True, passed_invariants=("I1",), failed_invariants=())
    )


def test_i34_classified_exceptions_expose_recovery() -> None:
    lost = AuthorityLostError("QUORUM_LOST: 1/2")
    assert lost.recovery.fail_closed is True
    assert lost.recovery.retry is False
    div = ReplicaDivergenceError("hash mismatch")
    assert div.recovery.invariant == "I11"
    assert semantics_for_exception(lost) is lost.recovery

"""Canonical I28 lease lifecycle."""

from __future__ import annotations

import pytest

from src.core.frontier.global_coordination import GlobalBudgetAggregate
from src.core.frontier.lease_status import (
    LeaseStatus,
    can_transition,
    is_outstanding,
    is_terminal,
    normalize_lease_status,
    require_transition,
)
from src.core.frontier.run_saga import DurableRunSagaEngine


def test_legacy_aliases_normalize() -> None:
    assert normalize_lease_status("ISSUED") is LeaseStatus.RESERVED
    assert normalize_lease_status("CLOSED") is LeaseStatus.CONSUMED
    assert normalize_lease_status("SETTLEMENT_PENDING") is LeaseStatus.ACTIVE
    assert normalize_lease_status("REQUESTED") is LeaseStatus.RESERVED


def test_legal_and_illegal_transitions() -> None:
    assert can_transition(LeaseStatus.RESERVED, LeaseStatus.ACTIVE)
    assert can_transition(LeaseStatus.RESERVED, LeaseStatus.COMPENSATED)
    assert can_transition(LeaseStatus.ACTIVE, LeaseStatus.CONSUMED)
    assert can_transition(LeaseStatus.ACTIVE, LeaseStatus.EXPIRED)
    assert can_transition(LeaseStatus.RESERVED, LeaseStatus.EXPIRED)
    assert can_transition(LeaseStatus.EXPIRED, LeaseStatus.COMPENSATED)
    assert not can_transition(LeaseStatus.CONSUMED, LeaseStatus.ACTIVE)
    assert not can_transition(LeaseStatus.ACTIVE, LeaseStatus.COMPENSATED)
    with pytest.raises(ValueError, match="Illegal lease transition"):
        require_transition(LeaseStatus.CONSUMED, LeaseStatus.RESERVED)


def test_outstanding_and_terminal() -> None:
    assert is_outstanding("ISSUED")
    assert is_outstanding(LeaseStatus.ACTIVE)
    assert not is_outstanding(LeaseStatus.CONSUMED)
    assert is_terminal("CLOSED")
    assert is_terminal(LeaseStatus.COMPENSATED)
    assert not is_terminal(LeaseStatus.EXPIRED)
    assert can_transition(LeaseStatus.EXPIRED, LeaseStatus.COMPENSATED)


def test_reserve_settle_consume() -> None:
    gb = GlobalBudgetAggregate(total_budget=100)
    ok, code = gb.reserve_sublease("sl", "run", "P-0001", 40)
    assert ok
    assert gb.subleases["sl"].status == LeaseStatus.RESERVED.value
    assert gb.outstanding_reserved == 40
    ok, code = gb.settle_return("sl", units_consumed=10, units_returned=30)
    assert ok
    assert code == "SUBLEASE_CONSUMED"
    assert gb.subleases["sl"].status == LeaseStatus.CONSUMED.value
    assert gb.outstanding_reserved == 0
    assert gb.verify_conservation()


def test_compensate_from_reserved_is_idempotent() -> None:
    gb = GlobalBudgetAggregate(total_budget=200)
    gb.reserve_sublease("sl_comp", "run_comp", "P-0001", 50)
    saga = DurableRunSagaEngine(global_budget=gb, placement_authority=None, partition_logs={})  # type: ignore[arg-type]
    ok, msg = saga.compensate_sublease("run_comp", "P-0001", "sl_comp")
    assert ok
    assert msg == "SUBLEASE_COMPENSATED_SUCCESS"
    assert gb.subleases["sl_comp"].status == LeaseStatus.COMPENSATED.value
    assert gb.available == 200
    ok2, msg2 = saga.compensate_sublease("run_comp", "P-0001", "sl_comp")
    assert ok2
    assert "already in terminal state" in msg2

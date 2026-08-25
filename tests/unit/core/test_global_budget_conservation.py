"""Unit tests for GlobalBudgetAggregate Invariant I5 conservation enforcement."""

from __future__ import annotations

from src.core.frontier.global_coordination import GlobalBudgetAggregate


def test_global_budget_conservation_success():
    budget = GlobalBudgetAggregate(total_budget=1000)
    assert budget.verify_conservation()

    # Reserve 100 units
    ok, msg = budget.reserve_sublease("sl-1", run_id="R-1", partition_id="P-0100", units=100)
    assert ok is True
    assert budget.available == 900
    assert budget.outstanding_reserved == 100
    assert budget.verify_conservation()

    # Settle valid return (40 consumed + 60 returned = 100 allocated)
    ok, msg = budget.settle_return("sl-1", units_consumed=40, units_returned=60)
    assert ok is True
    assert budget.consumed == 40
    assert budget.available == 960
    assert budget.outstanding_reserved == 0
    assert budget.verify_conservation()


def test_global_budget_rejects_conservation_violation():
    budget = GlobalBudgetAggregate(total_budget=1000)
    budget.reserve_sublease("sl-2", run_id="R-2", partition_id="P-0100", units=100)

    # Attempt to settle with unequal sum (50 + 30 = 80 != 100)
    ok, msg = budget.settle_return("sl-2", units_consumed=50, units_returned=30)
    assert ok is False
    assert "Budget conservation invariant violated" in msg
    # Budget must remain intact
    assert budget.verify_conservation()


def test_global_budget_rejects_duplicate_settlement():
    budget = GlobalBudgetAggregate(total_budget=1000)
    budget.reserve_sublease("sl-3", run_id="R-3", partition_id="P-0100", units=100)

    ok1, _ = budget.settle_return("sl-3", units_consumed=50, units_returned=50)
    assert ok1 is True

    # Duplicate settlement
    ok2, msg2 = budget.settle_return("sl-3", units_consumed=50, units_returned=50)
    assert ok2 is False
    assert "already consumed" in msg2
    assert budget.verify_conservation()


def test_global_budget_rejects_negative_units():
    budget = GlobalBudgetAggregate(total_budget=1000)
    budget.reserve_sublease("sl-4", run_id="R-4", partition_id="P-0100", units=100)

    ok, msg = budget.settle_return("sl-4", units_consumed=-10, units_returned=110)
    assert ok is False
    assert "Negative units not allowed" in msg
    assert budget.verify_conservation()

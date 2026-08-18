"""Similar-problem: now=0.0 is a valid clock, not 'use wall clock'."""

from __future__ import annotations

import pytest

from src.intelligence.risk.cisa_kev import KEVRecord
from src.intelligence.risk.compensating_controls import CompensatingControl
from src.intelligence.risk.risk_acceptance import (
    ACCEPTANCE_STATE_ACTIVE,
    RiskAcceptance,
    RiskAcceptanceManager,
)


@pytest.mark.unit
def test_risk_acceptance_honors_now_zero() -> None:
    acc = RiskAcceptance(
        acceptance_id="a1",
        finding_id="f1",
        accepted_until=100.0,
        state=ACCEPTANCE_STATE_ACTIVE,
    )
    assert acc.is_active(now=0.0) is True
    assert acc.days_until_expiry(now=0.0) == pytest.approx(100.0 / 86400.0)
    loaded = RiskAcceptance.from_dict(
        {
            "acceptance_id": "a2",
            "finding_id": "f2",
            "accepted_until": 50.0,
            "created_at": 0.0,
        }
    )
    assert loaded.created_at == 0.0
    mgr = RiskAcceptanceManager()
    mgr.add(acc)
    assert mgr.expiring_within(1, now=0.0)


@pytest.mark.unit
def test_control_and_kev_honor_now_zero() -> None:
    ctrl = CompensatingControl.from_dict(
        {
            "control_id": "c1",
            "finding_id": "f1",
            "control_type": "waf",
            "expires_at": 10.0,
            "created_at": 0.0,
        }
    )
    assert ctrl.created_at == 0.0
    assert ctrl.is_expired(now=0.0) is False
    assert ctrl.is_expired(now=10.0) is True
    rec = KEVRecord(cve="CVE-2024-0001", due_date="1970-01-02")
    days = rec.days_until_due(now=0.0)
    assert days is not None
    assert days > 0

"""Similar-problem: lifecycle timestamps of 0.0 are valid."""

from __future__ import annotations

import pytest

from src.intelligence.risk.finding_lifecycle import (
    FindingLifecycleManager,
    FindingLifecycleRecord,
    FindingState,
    SLAEvent,
)


@pytest.mark.unit
def test_lag_metrics_allow_epoch_zero() -> None:
    record = FindingLifecycleRecord(
        finding_id="f",
        discovered_at=0.0,
        triaged_at=86400.0,
        remediation_started_at=0.0,
        fixed_at=86400.0,
        verified_at=172800.0,
    )
    assert record.triage_lag_days == 1.0
    assert record.remediation_days == 1.0
    assert record.verification_days == 1.0


@pytest.mark.unit
def test_transition_and_from_dict_keep_zero_timestamp() -> None:
    mgr = FindingLifecycleManager()
    rec = mgr.transition("f", FindingState.TRIAGED, timestamp=0.0, force=True)
    assert rec.triaged_at == 0.0
    event = SLAEvent.from_dict(
        {
            "event_id": "e1",
            "finding_id": "f",
            "from_state": "OPEN",
            "to_state": "TRIAGED",
            "timestamp": 0.0,
        }
    )
    assert event.timestamp == 0.0

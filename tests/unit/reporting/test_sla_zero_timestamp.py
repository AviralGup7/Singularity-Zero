"""Regression: epoch timestamp 0 must not be treated as 'missing'."""

from __future__ import annotations

import pytest

from src.reporting.sla_tracker import SLATracker


@pytest.mark.unit
def test_check_sla_honors_epoch_zero_current_time() -> None:
    findings = [
        {
            "id": "f1",
            "severity": "critical",
            "timestamp": 0.0,
            "title": "crit",
        }
    ]
    report = SLATracker.check_sla_compliance(findings, current_time=0.0)
    assert report["overdue_count"] == 0
    assert report["compliant"][0]["age_seconds"] == 0.0
    later = SLATracker.check_sla_compliance(findings, current_time=15 * 86400)
    assert later["overdue_count"] == 1
    assert later["overdue"][0]["sla_status"] == "BREACHED"


@pytest.mark.unit
def test_lifecycle_summary_honors_epoch_zero() -> None:
    findings = [
        {
            "id": "f2",
            "severity": "high",
            "timestamp": 0.0,
            "lifecycle_state": "OPEN",
        }
    ]
    # Sabotage check: if timestamp 0 is dropped, lag is missing and avg stays 0
    # even after two days on the clock. Keeping 0 must yield a 2-day wait.
    summary = SLATracker.lifecycle_summary(findings, current_time=2 * 86400)
    assert summary["total"] == 1
    assert summary["avg_triage_lag_days"] == 2.0

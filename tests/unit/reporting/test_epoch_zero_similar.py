"""Similar-problem: epoch timestamp 0 must survive flatten/export/triage metrics."""

from __future__ import annotations

import pytest

from src.reporting.export_findings import flatten_finding_for_export
from src.reporting.report_artifacts import build_structured_report
from src.reporting.triage_audit import calculate_team_triage_metrics


@pytest.mark.unit
def test_triage_metrics_count_epoch_zero_discovery() -> None:
    metrics = calculate_team_triage_metrics(
        [],
        [
            {
                "id": "f0",
                "status": "TRIAGED",
                "discovered_at": 0.0,
                "triaged_at": 3600.0,
            }
        ],
    )
    assert metrics["triaged_count"] == 1
    assert metrics["avg_triage_hours"] == 1.0


@pytest.mark.unit
def test_flatten_and_structured_report_keep_zero_timestamp() -> None:
    finding = {
        "title": "x",
        "severity": "low",
        "timestamp": 0,
        "category": "info",
        "url": "https://ex.test/",
    }
    flat = flatten_finding_for_export(finding)
    assert flat["timestamp"] == 0
    report = build_structured_report(
        target_name="ex",
        run_id="r1",
        summary={},
        findings=[finding],
        diff_summary=None,
    )
    assert report["findings"][0]["timestamp"] == 0

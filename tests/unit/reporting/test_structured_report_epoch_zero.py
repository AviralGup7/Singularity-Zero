"""Similar-problem: structured report keeps numeric epoch-zero timestamps."""

from __future__ import annotations

import pytest

from src.reporting.report_artifacts import build_structured_report


@pytest.mark.unit
def test_structured_report_keeps_zero_timestamp() -> None:
    finding = {
        "title": "x",
        "severity": "low",
        "timestamp": 0,
        "category": "info",
        "url": "https://ex.test/",
    }
    report = build_structured_report(
        target_name="ex",
        run_id="r1",
        summary={},
        findings=[finding],
        diff_summary=None,
    )
    assert report["findings"][0]["timestamp"] == 0

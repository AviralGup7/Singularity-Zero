"""Coverage and checksum regression for baseline tracking."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.learning.baseline_tracker import (
    BaselineTracker,
    RunBaseline,
    compute_baseline_from_run,
)


def _baseline(**overrides: object) -> RunBaseline:
    payload: dict[str, object] = {
        "run_id": "run-1",
        "timestamp": 1.0,
        "scope_size": 3,
        "subdomains_found": 4,
        "live_hosts_found": 2,
        "urls_found": 10,
        "parameters_found": 5,
        "total_findings": 8,
        "critical_findings": 1,
        "high_findings": 2,
        "medium_findings": 3,
        "low_findings": 1,
        "info_findings": 1,
        "false_positive_rate": 0.1,
        "avg_confidence": 0.7,
        "tool_success_rate": 0.9,
        "recon_coverage_percent": 80.0,
        "scan_duration_seconds": 12.0,
        "findings_per_subdomain": 2.0,
    }
    payload.update(overrides)
    return RunBaseline(**payload)  # type: ignore[arg-type]


@pytest.mark.unit
def test_compute_baseline_from_run_counts_and_duration() -> None:
    result = compute_baseline_from_run(
        "abc",
        {
            "scope_entries": ["a.com", "b.com"],
            "module_metrics": {
                "subdomains": {"subdomains_found": 4, "duration_seconds": 2},
                "live_hosts": {"live_hosts_found": 3, "duration_seconds": 1.5},
                "urls": {"urls_found": 9},
                "parameters": {"parameters_found": 6, "duration_seconds": 0.5},
            },
            "reportable_findings": [
                {
                    "severity": "critical",
                    "confidence": 0.9,
                    "asset_type": "api",
                    "decision": "TRUE_POSITIVE",
                },
                {
                    "severity": "high",
                    "confidence": 0.5,
                    "asset_type": "api",
                    "decision": "FALSE_POSITIVE",
                },
                {"severity": "info", "confidence": 0.2, "asset_type": "web"},
            ],
            "tool_success_rate": 0.8,
            "recon_coverage_percent": 70.0,
        },
    )
    assert result.total_findings == 3
    assert result.critical_findings == 1
    assert result.high_findings == 1
    assert result.scan_duration_seconds == 4.0
    assert result.asset_type_fp_rate["api"] == 0.5
    assert result.checksum


@pytest.mark.unit
def test_load_skips_tampered_baselines(tmp_path: Path) -> None:
    good = _baseline(run_id="good", timestamp=2.0)
    path = tmp_path / "baselines.json"
    path.write_text(
        json.dumps(
            {
                "window_size": 5,
                "baselines": [
                    {**good.__dict__},
                    {
                        **good.__dict__,
                        "run_id": "evil",
                        "total_findings": 99,
                        "checksum": "deadbeef",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    tracker = BaselineTracker()
    tracker.load(path)
    assert [item.run_id for item in tracker._baselines] == ["good"]


@pytest.mark.unit
def test_anomaly_score_flags_large_deviation() -> None:
    tracker = BaselineTracker()
    tracker.add(_baseline(run_id="a", timestamp=1.0, total_findings=8, critical_findings=1))
    tracker.add(_baseline(run_id="b", timestamp=2.0, total_findings=9, critical_findings=1))
    current = _baseline(run_id="c", timestamp=3.0, total_findings=80, critical_findings=20)
    report = tracker.compute_anomaly_score(current)
    assert report["anomaly_score"] > 0
    metrics = {item["metric"] for item in report["anomalies"]}
    assert "total_findings" in metrics

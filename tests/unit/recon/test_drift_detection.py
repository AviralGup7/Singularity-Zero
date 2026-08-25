"""Unit tests for the Continuous Discovery & Drift Detection module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from src.recon.drift_detection import DriftDetector


def test_drift_detector_snapshots_and_deltas():
    """Verify that snapshots are correctly loaded, saved, and deltas calculated."""
    with tempfile.TemporaryDirectory() as tmpdir:
        detector = DriftDetector(tmpdir)
        target = "test-target.com"

        # 1. First run (empty snapshot baseline)
        baseline = {
            "subdomains": ["admin.test-target.com", "www.test-target.com"],
            "live_hosts": ["www.test-target.com"],
            "open_ports": ["www.test-target.com:443"],
            "urls": ["https://www.test-target.com/index.html"],
        }

        drift1 = detector.compute_drift(target, baseline)
        assert drift1["has_drift"] is False  # Baseline should not show drift

        # Verify snapshot file exists
        snapshot_path = Path(tmpdir) / "recon_snapshots" / "test-target.com_snapshot.json"
        assert snapshot_path.exists()

        # 2. Second run (introducing drift: added and removed elements)
        current = {
            "subdomains": [
                "api.test-target.com",
                "www.test-target.com",
            ],  # admin removed, api added
            "live_hosts": ["www.test-target.com", "api.test-target.com"],  # api added
            "open_ports": ["www.test-target.com:443", "api.test-target.com:80"],  # api:80 added
            "urls": [],  # URL removed
        }

        drift2 = detector.compute_drift(target, current)
        assert drift2["has_drift"] is True

        deltas = drift2["deltas"]
        assert deltas["subdomains"]["added"] == ["api.test-target.com"]
        assert deltas["subdomains"]["removed"] == ["admin.test-target.com"]
        assert deltas["live_hosts"]["added"] == ["api.test-target.com"]
        assert deltas["open_ports"]["added"] == ["api.test-target.com:80"]
        assert deltas["urls"]["removed"] == ["https://www.test-target.com/index.html"]

        # Verify CLI output rendering matches
        cli_summary = detector.render_cli_summary(drift2)
        assert "Reconnaissance Asset Drift Detected!" in cli_summary
        assert "SUBDOMAINS" in cli_summary
        assert "api.test-target.com" in cli_summary

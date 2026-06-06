from pathlib import Path
from src.learning.telemetry_store import TelemetryStore



class TestTelemetryStoreScanRuns:
    """Tests for scan run operations."""

    def test_record_and_get_scan_run(self, store, sample_run):
        store.record_scan_run(sample_run)
        result = store.get_scan_run("test-run-001")
        assert result is not None
        assert result["target_name"] == "example.com"
        assert result["mode"] == "deep"
        assert result["total_findings"] == 25

    def test_get_nonexistent_run(self, store):
        result = store.get_scan_run("nonexistent")
        assert result is None

    def test_get_recent_runs(self, store, sample_run):
        store.record_scan_run(sample_run)
        runs = store.get_recent_runs()
        assert len(runs) >= 1
        assert runs[0]["run_id"] == "test-run-001"

    def test_get_recent_runs_by_target(self, store, sample_run):
        store.record_scan_run(sample_run)
        runs = store.get_recent_runs(target="example.com")
        assert len(runs) >= 1
        runs = store.get_recent_runs(target="other.com")
        assert len(runs) == 0

    def test_get_recent_runs_limit(self, store, sample_run):
        for i in range(30):
            run = dict(sample_run)
            run["run_id"] = f"run-{i:03d}"
            store.record_scan_run(run)
        runs = store.get_recent_runs(limit=5)
        assert len(runs) == 5

    def test_count_runs_for_target(self, store, sample_run):
        store.record_scan_run(sample_run)
        count = store.count_runs_for_target("example.com")
        assert count == 1

    def test_count_runs_for_target_none(self, store):
        count = store.count_runs_for_target("nonexistent.com")
        assert count == 0

    def test_upsert_replaces_existing(self, store, sample_run):
        store.record_scan_run(sample_run)
        updated = dict(sample_run)
        updated["total_findings"] = 50
        store.record_scan_run(updated)
        result = store.get_scan_run("test-run-001")
        assert result["total_findings"] == 50

    def test_record_multiple_runs(self, store, sample_run):
        for i in range(5):
            run = dict(sample_run)
            run["run_id"] = f"run-{i}"
            run["target_name"] = f"target-{i}.com"
            store.record_scan_run(run)
        assert store.count_runs_for_target("target-2.com") == 1
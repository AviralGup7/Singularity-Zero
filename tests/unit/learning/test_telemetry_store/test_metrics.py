from pathlib import Path
from src.learning.telemetry_store import TelemetryStore



class TestTelemetryStoreMetrics:
    """Tests for performance metrics operations."""

    def test_record_and_get_metrics(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.record_metric("test-run-001", "precision", 0.85, "detection")
        metrics = store.get_metrics_for_run("test-run-001")
        assert len(metrics) == 1
        assert metrics[0]["metric_name"] == "precision"
        assert metrics[0]["metric_value"] == 0.85

    def test_record_multiple_metrics(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.record_metric("test-run-001", "precision", 0.85, "detection")
        store.record_metric("test-run-001", "recall", 0.78, "detection")
        store.record_metric("test-run-001", "f1", 0.81, "detection")
        metrics = store.get_metrics_for_run("test-run-001")
        assert len(metrics) == 3

    def test_record_metric_upsert(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.record_metric("test-run-001", "precision", 0.85, "detection")
        store.record_metric("test-run-001", "precision", 0.90, "detection")
        metrics = store.get_metrics_for_run("test-run-001")
        assert len(metrics) == 1
        assert metrics[0]["metric_value"] == 0.90

    def test_get_metrics_for_run_empty(self, store, sample_run):
        store.record_scan_run(sample_run)
        metrics = store.get_metrics_for_run("test-run-001")
        assert len(metrics) == 0
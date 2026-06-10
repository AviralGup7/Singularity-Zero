class TestTelemetryStoreThresholds:
    """Tests for threshold history operations."""

    def test_record_threshold_history(self, store, sample_run):
        store.record_scan_run(sample_run)
        row = {
            "history_id": "th-001",
            "run_id": "test-run-001",
            "category": None,
            "low_threshold": 0.45,
            "medium_threshold": 0.58,
            "high_threshold": 0.72,
            "observed_fp_rate": 0.2,
            "target_fp_rate": 0.15,
            "error": 0.05,
            "adjustment": -0.01,
            "is_converged": 0,
            "recorded_at": "2026-04-01T10:15:00",
        }
        store.record_threshold_history(row)
        history = store.get_threshold_history(run_id="test-run-001")
        assert len(history) == 1
        assert history[0]["low_threshold"] == 0.45

    def test_record_threshold_history_with_bool(self, store, sample_run):
        store.record_scan_run(sample_run)
        row = {
            "history_id": "th-bool-001",
            "run_id": "test-run-001",
            "category": "idor",
            "low_threshold": 0.45,
            "medium_threshold": 0.58,
            "high_threshold": 0.72,
            "observed_fp_rate": 0.2,
            "target_fp_rate": 0.15,
            "error": 0.05,
            "adjustment": -0.01,
            "is_converged": True,
            "recorded_at": "2026-04-01T10:15:00",
        }
        store.record_threshold_history(row)
        history = store.get_threshold_history(run_id="test-run-001")
        assert len(history) == 1
        assert history[0]["is_converged"] == 1

    def test_get_threshold_history_by_category(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.record_threshold_history(
            {
                "history_id": "th-cat-001",
                "run_id": "test-run-001",
                "category": "idor",
                "low_threshold": 0.4,
                "medium_threshold": 0.5,
                "high_threshold": 0.6,
                "observed_fp_rate": 0.1,
                "target_fp_rate": 0.1,
                "error": 0.0,
                "adjustment": 0.0,
                "is_converged": 0,
                "recorded_at": "2026-04-01T10:15:00",
            }
        )
        history = store.get_threshold_history(category="idor")
        assert len(history) == 1

    def test_get_threshold_history_empty(self, store):
        history = store.get_threshold_history(run_id="nonexistent")
        assert len(history) == 0

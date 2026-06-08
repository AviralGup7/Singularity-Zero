


class TestTelemetryStorePluginStats:
    """Tests for plugin statistics operations."""

    def test_record_and_get_plugin_stats(self, store, sample_run):
        store.record_scan_run(sample_run)
        stat = {
            "stat_id": "ps-001",
            "run_id": "test-run-001",
            "plugin_name": "idor_candidate_finder",
            "findings_produced": 10,
            "true_positives": 8,
            "false_positives": 2,
            "execution_time_ms": 1500.0,
            "precision": 0.8,
            "recall": 0.75,
            "recorded_at": "2026-04-01T10:15:00",
        }
        store.record_plugin_stat(stat)
        stats = store.get_plugin_stats(run_id="test-run-001")
        assert len(stats) == 1
        assert stats[0]["plugin_name"] == "idor_candidate_finder"

    def test_get_plugin_stats_all(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.record_plugin_stat(
            {
                "stat_id": "ps-all-001",
                "run_id": "test-run-001",
                "plugin_name": "test_plugin",
                "findings_produced": 5,
                "true_positives": 4,
                "false_positives": 1,
                "execution_time_ms": 500.0,
                "precision": 0.8,
                "recall": 0.7,
                "recorded_at": "2026-04-01T10:15:00",
            }
        )
        stats = store.get_plugin_stats()
        assert len(stats) >= 1

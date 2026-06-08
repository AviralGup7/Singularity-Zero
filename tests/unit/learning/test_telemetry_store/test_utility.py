


class TestTelemetryStoreUtility:
    """Tests for utility operations."""

    def test_get_db_size(self, store, sample_run):
        store.record_scan_run(sample_run)
        sizes = store.get_db_size()
        assert "scan_runs" in sizes
        assert sizes["scan_runs"] == 1

    def test_run_maintenance(self, store):
        result = store.run_maintenance()
        assert result["status"] == "completed"
        assert "size" in result

    def test_delete_expired_records(self, store, sample_run):
        store.record_scan_run(sample_run)
        deleted = store.delete_expired_records("scan_runs", "2020-01-01T00:00:00", "created_at")
        assert deleted == 0

    def test_get_fp_rate_for_pattern_empty(self, store):
        rate = store.get_fp_rate_for_pattern("idor", "test_plugin")
        assert rate == 0.5

    def test_get_confidence_distribution_empty(self, store):
        dist = store.get_confidence_distribution("idor")
        assert dist == []

    def test_get_parameter_profile_empty(self, store):
        profile = store.get_parameter_profile("id")
        assert profile is None

    def test_count_findings_for_param_empty(self, store):
        count = store.count_findings_for_param("id")
        assert count == 0

    def test_get_fp_rate_for_param_empty(self, store):
        rate = store.get_fp_rate_for_param("id")
        assert rate == 0.0

    def test_find_previous_findings_empty(self, store):
        findings = store.find_previous_findings("/api/users", "idor", "run-001")
        assert findings == []

    def test_find_cross_target_findings_empty_list(self, store):
        findings = store.find_cross_target_findings([], "idor", "example.com")
        assert findings == []

    def test_find_cross_target_findings_empty(self, store):
        findings = store.find_cross_target_findings(["nginx"], "idor", "example.com")
        assert findings == []

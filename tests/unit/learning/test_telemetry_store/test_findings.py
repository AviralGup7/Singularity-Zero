


class TestTelemetryStoreFindings:
    """Tests for finding operations."""

    def test_record_and_get_findings(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        store.record_finding(sample_finding)
        findings = store.get_findings_for_run("test-run-001")
        assert len(findings) == 1
        assert findings[0]["category"] == "idor"
        assert findings[0]["severity"] == "high"

    def test_get_findings_empty(self, store, sample_run):
        store.record_scan_run(sample_run)
        findings = store.get_findings_for_run("test-run-001")
        assert len(findings) == 0

    def test_count_findings_for_target(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        store.record_finding(sample_finding)
        count = store.count_findings_for_target("example.com")
        assert count == 1

    def test_count_findings_for_target_none(self, store):
        count = store.count_findings_for_target("nonexistent.com")
        assert count == 0

    def test_count_validated_findings_for_target(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        finding = dict(sample_finding)
        finding["lifecycle_state"] = "VALIDATED"
        finding["finding_id"] = "validated-001"
        store.record_finding(finding)
        count = store.count_validated_findings_for_target("example.com")
        assert count == 1

    def test_record_multiple_findings(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        for i in range(3):
            f = dict(sample_finding)
            f["finding_id"] = f"finding-{i}"
            store.record_finding(f)
        findings = store.get_findings_for_run("test-run-001")
        assert len(findings) == 3

    def test_findings_ordered_by_confidence(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        f1 = dict(sample_finding)
        f1["finding_id"] = "f-low"
        f1["confidence"] = 0.3
        f2 = dict(sample_finding)
        f2["finding_id"] = "f-high"
        f2["confidence"] = 0.9
        store.record_finding(f1)
        store.record_finding(f2)
        findings = store.get_findings_for_run("test-run-001")
        assert findings[0]["confidence"] >= findings[1]["confidence"]

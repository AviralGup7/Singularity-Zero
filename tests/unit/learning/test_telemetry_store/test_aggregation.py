from pathlib import Path
from src.learning.telemetry_store import TelemetryStore



class TestTelemetryStoreAggregation:
    """Tests for aggregation helper methods."""

    def test_get_fp_rate_for_pattern(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        event = dict(sample_feedback_event)
        event["event_id"] = "fb-fp-rate-001"
        event["was_false_positive"] = True
        store.insert_feedback_event(event)
        rate = store.get_fp_rate_for_pattern("idor", "idor_candidate_finder")
        assert rate == 1.0

    def test_get_confidence_distribution(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        store.insert_feedback_event(sample_feedback_event)
        dist = store.get_confidence_distribution("idor")
        assert len(dist) == 1
        assert dist[0] == 0.75

    def test_get_parameter_profile(self, store):
        profile = {
            "profile_id": "pp-001",
            "parameter_name": "user_id",
            "canonical_type": "identifier",
            "sub_type": "numeric",
            "entity_context": "user",
            "endpoint_context": "/api/users",
            "location": "query",
            "sensitivity_level": "high",
            "fuzz_strategy": "boundary",
            "historical_findings": 5,
            "historical_fp_rate": 0.2,
            "classification_confidence": 0.85,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        conn = store._get_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO parameter_profiles
               (profile_id, parameter_name, canonical_type, sub_type,
                entity_context, endpoint_context, location, sensitivity_level,
                fuzz_strategy, historical_findings, historical_fp_rate,
                classification_confidence, first_seen, last_seen, updated_at)
               VALUES (:profile_id, :parameter_name, :canonical_type, :sub_type,
                       :entity_context, :endpoint_context, :location, :sensitivity_level,
                       :fuzz_strategy, :historical_findings, :historical_fp_rate,
                       :classification_confidence, :first_seen, :last_seen, :updated_at)""",
            profile,
        )
        conn.commit()
        result = store.get_parameter_profile("user_id")
        assert result["canonical_type"] == "identifier"

    def test_count_findings_for_param(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        store.record_finding(sample_finding)
        count = store.count_findings_for_param("id")
        assert count == 1

    def test_get_fp_rate_for_param(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        event = dict(sample_feedback_event)
        event["event_id"] = "fb-fp-param-001"
        event["was_false_positive"] = True
        event["parameter_name"] = "id"
        store.insert_feedback_event(event)
        rate = store.get_fp_rate_for_param("id")
        assert rate == 1.0

    def test_find_previous_findings(self, store, sample_run, sample_finding):
        store.record_scan_run(sample_run)
        store.record_finding(sample_finding)
        store.record_scan_run(
            {
                "run_id": "test-run-002",
                "target_name": "example.com",
                "mode": "deep",
                "start_time": "2026-04-02T10:00:00",
                "end_time": "2026-04-02T10:15:00",
                "status": "completed",
                "total_urls": 100,
                "total_endpoints": 50,
                "total_findings": 10,
                "validated_findings": 5,
                "false_positives": 2,
                "scan_duration_sec": 900.0,
                "config_hash": "def456",
                "feedback_applied": False,
            }
        )
        store.record_finding(
            {
                "finding_id": "finding-002",
                "run_id": "test-run-002",
                "category": "idor",
                "title": "Another IDOR",
                "url": "https://api.example.com/api/v1/users/456",
                "severity": "medium",
                "confidence": 0.6,
                "score": 6.0,
                "decision": "MEDIUM",
                "lifecycle_state": "DETECTED",
                "cvss_score": 6.0,
                "plugin_name": "idor_candidate_finder",
                "endpoint_base": "https://api.example.com/api/v1/users",
                "host": "api.example.com",
                "parameter_name": "id",
                "parameter_type": "identifier",
                "evidence": "Another finding",
                "response_status": 200,
                "response_body_hash": "hash456",
            }
        )
        findings = store.find_previous_findings(
            "https://api.example.com/api/v1/users",
            "idor",
            "test-run-002",
        )
        assert len(findings) == 1
        assert findings[0]["run_id"] == "test-run-001"

    def test_find_cross_target_findings(self, store):
        store.record_scan_run(
            {
                "run_id": "cross-001",
                "target_name": "other-target.com",
                "mode": "deep",
                "start_time": "2026-04-01T10:00:00",
                "end_time": "2026-04-01T10:15:00",
                "status": "completed",
                "total_urls": 100,
                "total_endpoints": 50,
                "total_findings": 10,
                "validated_findings": 5,
                "false_positives": 2,
                "scan_duration_sec": 900.0,
                "config_hash": "hash1",
                "feedback_applied": False,
            }
        )
        store.record_finding(
            {
                "finding_id": "cross-finding-001",
                "run_id": "cross-001",
                "category": "idor",
                "title": "Cross target IDOR",
                "url": "https://api.other-target.com/api/users/1",
                "severity": "high",
                "confidence": 0.8,
                "score": 7.5,
                "decision": "HIGH",
                "lifecycle_state": "DETECTED",
                "cvss_score": 7.0,
                "plugin_name": "idor_finder",
                "endpoint_base": "https://api.other-target.com/api/users",
                "host": "api.other-target.com",
                "parameter_name": "id",
                "parameter_type": "identifier",
                "evidence": "Cross target",
                "response_status": 200,
                "response_body_hash": "cross-hash",
            }
        )
        findings = store.find_cross_target_findings(
            ["nginx"],
            "idor",
            "example.com",
        )
        assert len(findings) == 1
        assert findings[0]["target_name"] == "other-target.com"
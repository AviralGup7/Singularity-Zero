


class TestTelemetryStoreFeedbackEvents:
    """Tests for feedback event operations."""

    def test_insert_and_get_feedback(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        store.insert_feedback_event(sample_feedback_event)
        events = store.get_feedback_events_for_run("test-run-001")
        assert len(events) == 1
        assert events[0]["finding_category"] == "idor"

    def test_insert_feedback_with_bool_values(self, store, sample_run):
        store.record_scan_run(sample_run)
        event = {
            "event_id": "fb-bool-test",
            "run_id": "test-run-001",
            "timestamp": "2026-04-01T10:10:00",
            "target_host": "api.example.com",
            "target_endpoint": "https://api.example.com/api/v1/users",
            "finding_category": "idor",
            "finding_severity": "high",
            "finding_confidence": 0.75,
            "finding_decision": "MEDIUM",
            "plugin_name": "idor_candidate_finder",
            "parameter_name": "id",
            "parameter_type": "identifier",
            "was_validated": True,
            "was_false_positive": False,
            "validation_method": None,
            "response_delta_score": 2,
            "endpoint_type": "API",
            "tech_stack": ["nginx", "python"],
            "scan_mode": "deep",
            "feedback_weight": 1.5,
        }
        store.insert_feedback_event(event)
        events = store.get_feedback_events_for_run("test-run-001")
        assert len(events) == 1
        assert events[0]["was_validated"] == 1
        assert events[0]["was_false_positive"] == 0

    def test_recompute_feedback_weights(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        store.insert_feedback_event(sample_feedback_event)
        updated = store.recompute_feedback_weights("test-run-001")
        assert updated >= 1

    def test_recompute_feedback_weights_empty(self, store, sample_run):
        store.record_scan_run(sample_run)
        updated = store.recompute_feedback_weights("test-run-001")
        assert updated == 0

    def test_get_feedback_events_for_endpoint(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        store.insert_feedback_event(sample_feedback_event)
        events = store.get_feedback_events_for_endpoint(
            "https://api.example.com/api/v1/users",
            "api.example.com",
        )
        assert len(events) == 1

    def test_get_feedback_events_for_endpoint_none(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        store.insert_feedback_event(sample_feedback_event)
        events = store.get_feedback_events_for_endpoint(
            "https://other.com/api",
            "other.com",
        )
        assert len(events) == 0

    def test_multiple_feedback_events(self, store, sample_run, sample_feedback_event):
        store.record_scan_run(sample_run)
        for i in range(3):
            event = dict(sample_feedback_event)
            event["event_id"] = f"fb-event-{i}"
            store.insert_feedback_event(event)
        events = store.get_feedback_events_for_run("test-run-001")
        assert len(events) == 3

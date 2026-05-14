"""Tests for the telemetry store."""

from pathlib import Path

from src.learning.telemetry_store import TelemetryStore


class TestTelemetryStoreInit:
    """Tests for TelemetryStore initialization."""

    def test_creates_database(self, tmp_db_path):
        store = TelemetryStore(tmp_db_path)
        store.initialize()
        assert tmp_db_path.exists()
        store.close()

    def test_creates_parent_directory(self, tmp_path):
        db_path = tmp_path / "subdir" / "telemetry.db"
        store = TelemetryStore(db_path)
        store.initialize()
        assert db_path.exists()
        store.close()

    def test_default_path(self):
        store = TelemetryStore()
        assert store.db_path.name == "telemetry.db"
        assert store.db_path.parent.name == ".pipeline"

    def test_context_manager(self, tmp_db_path):
        with TelemetryStore(tmp_db_path) as store:
            assert store._initialized is True

    def test_idempotent_initialize(self, tmp_db_path):
        store = TelemetryStore(tmp_db_path)
        store.initialize()
        store.initialize()
        assert store._initialized is True
        store.close()

    def test_close_is_idempotent(self, tmp_db_path):
        store = TelemetryStore(tmp_db_path)
        store.initialize()
        store.close()
        store.close()

    def test_accepts_string_path(self, tmp_path):
        db_path = str(tmp_path / "str_path.db")
        store = TelemetryStore(db_path)
        store.initialize()
        assert Path(db_path).exists()
        store.close()


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


class TestTelemetryStoreFPPatterns:
    """Tests for FP pattern operations."""

    def test_upsert_and_get_fp_patterns(self, store):
        pattern = {
            "pattern_id": "fp-test-001",
            "category": "waf_block",
            "status_code_pattern": "[403, 406]",
            "body_pattern": '["blocked"]',
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 5,
            "confirmed_fp_count": 4,
            "confirmed_tp_count": 1,
            "fp_probability": 0.8,
            "confidence": 0.7,
            "is_active": 1,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        patterns = store.get_fp_patterns()
        assert len(patterns) == 1
        assert patterns[0]["category"] == "waf_block"

    def test_get_active_fp_pattern_count(self, store):
        pattern = {
            "pattern_id": "fp-test-002",
            "category": "rate_limit",
            "status_code_pattern": "[429]",
            "body_pattern": '["rate limit"]',
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 3,
            "confirmed_fp_count": 3,
            "confirmed_tp_count": 0,
            "fp_probability": 0.9,
            "confidence": 0.8,
            "is_active": 1,
            "suppression_action": "suppress",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        count = store.get_active_fp_pattern_count()
        assert count == 1

    def test_get_fp_patterns_by_category(self, store):
        pattern1 = {
            "pattern_id": "fp-cat-001",
            "category": "waf_block",
            "status_code_pattern": "[403]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 1,
            "confirmed_tp_count": 0,
            "fp_probability": 0.7,
            "confidence": 0.5,
            "is_active": 1,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        pattern2 = {
            "pattern_id": "fp-cat-002",
            "category": "rate_limit",
            "status_code_pattern": "[429]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 1,
            "confirmed_tp_count": 0,
            "fp_probability": 0.7,
            "confidence": 0.5,
            "is_active": 1,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern1)
        store.upsert_fp_pattern(pattern2)
        patterns = store.get_fp_patterns(category="waf_block")
        assert len(patterns) == 1
        assert patterns[0]["category"] == "waf_block"

    def test_get_fp_patterns_inactive_excluded(self, store):
        pattern = {
            "pattern_id": "fp-inactive-001",
            "category": "noise",
            "status_code_pattern": "[500]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 0,
            "confirmed_tp_count": 1,
            "fp_probability": 0.3,
            "confidence": 0.5,
            "is_active": 0,
            "suppression_action": "flag",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        patterns = store.get_fp_patterns(active_only=True)
        assert len(patterns) == 0

    def test_upsert_fp_pattern_with_bool_is_active(self, store):
        pattern = {
            "pattern_id": "fp-bool-001",
            "category": "test",
            "status_code_pattern": "[404]",
            "body_pattern": "[]",
            "header_pattern": "{}",
            "response_similarity": 0.9,
            "first_seen": "2026-04-01T10:00:00",
            "last_seen": "2026-04-01T10:00:00",
            "occurrence_count": 1,
            "confirmed_fp_count": 1,
            "confirmed_tp_count": 0,
            "fp_probability": 0.7,
            "confidence": 0.5,
            "is_active": True,
            "suppression_action": "downgrade",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_fp_pattern(pattern)
        patterns = store.get_fp_patterns()
        assert len(patterns) == 1
        assert patterns[0]["is_active"] == 1


class TestTelemetryStoreGraph:
    """Tests for graph operations."""

    def test_upsert_graph_node(self, store, sample_run):
        store.record_scan_run(sample_run)
        node = {
            "node_id": "node-001",
            "node_type": "finding",
            "label": "IDOR finding",
            "properties": '{"category": "idor"}',
            "run_id": "test-run-001",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_graph_node(node)
        nodes = store.get_graph_nodes(node_type="finding")
        assert len(nodes) == 1

    def test_upsert_graph_node_with_dict_properties(self, store):
        node = {
            "node_id": "node-dict-001",
            "node_type": "finding",
            "label": "Dict props",
            "properties": {"category": "xss", "severity": "medium"},
            "run_id": None,
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        store.upsert_graph_node(node)
        nodes = store.get_graph_nodes(node_type="finding")
        assert len(nodes) == 1

    def test_upsert_graph_edge(self, store):
        store.upsert_graph_node(
            {
                "node_id": "src-001",
                "node_type": "finding",
                "label": "Source",
                "properties": "{}",
                "run_id": None,
                "created_at": "2026-04-01T10:00:00",
                "updated_at": "2026-04-01T10:00:00",
            }
        )
        store.upsert_graph_node(
            {
                "node_id": "tgt-001",
                "node_type": "finding",
                "label": "Target",
                "properties": "{}",
                "run_id": None,
                "created_at": "2026-04-01T10:00:00",
                "updated_at": "2026-04-01T10:00:00",
            }
        )
        edge = {
            "edge_id": "edge-001",
            "source_node_id": "src-001",
            "target_node_id": "tgt-001",
            "edge_type": "co_occurs",
            "weight": 0.8,
            "confidence": 0.7,
            "properties": "{}",
            "created_at": "2026-04-01T10:00:00",
        }
        store.upsert_graph_edge(edge)
        edges = store.get_graph_edges(source_node_id="src-001")
        assert len(edges) == 1

    def test_upsert_graph_edge_with_dict_properties(self, store):
        store.upsert_graph_node(
            {
                "node_id": "src-002",
                "node_type": "finding",
                "label": "Source",
                "properties": "{}",
                "run_id": None,
                "created_at": "2026-04-01T10:00:00",
                "updated_at": "2026-04-01T10:00:00",
            }
        )
        store.upsert_graph_node(
            {
                "node_id": "tgt-002",
                "node_type": "finding",
                "label": "Target",
                "properties": "{}",
                "run_id": None,
                "created_at": "2026-04-01T10:00:00",
                "updated_at": "2026-04-01T10:00:00",
            }
        )
        edge = {
            "edge_id": "edge-002",
            "source_node_id": "src-002",
            "target_node_id": "tgt-002",
            "edge_type": "chains_to",
            "weight": 0.9,
            "confidence": 0.8,
            "properties": {"chain_type": "auth_bypass"},
            "created_at": "2026-04-01T10:00:00",
        }
        store.upsert_graph_edge(edge)
        edges = store.get_graph_edges(source_node_id="src-002")
        assert len(edges) == 1

    def test_get_graph_nodes_by_run_id(self, store, sample_run):
        store.record_scan_run(sample_run)
        store.upsert_graph_node(
            {
                "node_id": "node-run-001",
                "node_type": "endpoint",
                "label": "Test endpoint",
                "properties": "{}",
                "run_id": "test-run-001",
                "created_at": "2026-04-01T10:00:00",
                "updated_at": "2026-04-01T10:00:00",
            }
        )
        nodes = store.get_graph_nodes(run_id="test-run-001")
        assert len(nodes) == 1

    def test_get_graph_edges_by_type(self, store):
        store.upsert_graph_node(
            {
                "node_id": "src-type",
                "node_type": "finding",
                "label": "Source",
                "properties": "{}",
                "run_id": None,
                "created_at": "2026-04-01T10:00:00",
                "updated_at": "2026-04-01T10:00:00",
            }
        )
        store.upsert_graph_node(
            {
                "node_id": "tgt-type",
                "node_type": "finding",
                "label": "Target",
                "properties": "{}",
                "run_id": None,
                "created_at": "2026-04-01T10:00:00",
                "updated_at": "2026-04-01T10:00:00",
            }
        )
        store.upsert_graph_edge(
            {
                "edge_id": "edge-type-001",
                "source_node_id": "src-type",
                "target_node_id": "tgt-type",
                "edge_type": "co_occurs",
                "weight": 0.5,
                "confidence": 0.5,
                "properties": "{}",
                "created_at": "2026-04-01T10:00:00",
            }
        )
        edges = store.get_graph_edges(edge_type="co_occurs")
        assert len(edges) == 1

    def test_get_graph_nodes_empty(self, store):
        nodes = store.get_graph_nodes(node_type="nonexistent")
        assert len(nodes) == 0

    def test_get_graph_edges_empty(self, store):
        edges = store.get_graph_edges(source_node_id="nonexistent")
        assert len(edges) == 0


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


class TestTelemetryStoreAttackChains:
    """Tests for attack chain operations."""

    def test_record_and_get_attack_chains(self, store):
        chain = {
            "chain_id": "chain-001",
            "pattern_name": "auth_bypass_chain",
            "description": "IDOR leads to auth bypass",
            "finding_ids": '["f1", "f2"]',
            "confidence": 0.85,
            "risk_score": 8.5,
            "validation_status": "pending",
            "validation_result": None,
            "detected_at": "2026-04-01T10:20:00",
        }
        store.record_attack_chain(chain)
        chains = store.get_attack_chains()
        assert len(chains) == 1
        assert chains[0]["pattern_name"] == "auth_bypass_chain"

    def test_get_attack_chains_by_pattern(self, store):
        store.record_attack_chain(
            {
                "chain_id": "chain-pattern-001",
                "pattern_name": "xss_chain",
                "description": "XSS chain",
                "finding_ids": '["f3"]',
                "confidence": 0.7,
                "risk_score": 6.0,
                "validation_status": "confirmed",
                "validation_result": "verified",
                "detected_at": "2026-04-01T10:20:00",
            }
        )
        chains = store.get_attack_chains(pattern_name="xss_chain")
        assert len(chains) == 1

    def test_get_attack_chains_by_status(self, store):
        store.record_attack_chain(
            {
                "chain_id": "chain-status-001",
                "pattern_name": "test_chain",
                "description": "Test",
                "finding_ids": '["f4"]',
                "confidence": 0.6,
                "risk_score": 5.0,
                "validation_status": "pending",
                "validation_result": None,
                "detected_at": "2026-04-01T10:20:00",
            }
        )
        chains = store.get_attack_chains(status="pending")
        assert len(chains) == 1

    def test_get_attack_chains_limit(self, store):
        for i in range(10):
            store.record_attack_chain(
                {
                    "chain_id": f"chain-limit-{i:03d}",
                    "pattern_name": "test",
                    "description": "Test",
                    "finding_ids": f'["f{i}"]',
                    "confidence": 0.5,
                    "risk_score": float(i),
                    "validation_status": "pending",
                    "validation_result": None,
                    "detected_at": "2026-04-01T10:20:00",
                }
            )
        chains = store.get_attack_chains(limit=3)
        assert len(chains) == 3


class TestTelemetryStoreConfidenceModels:
    """Tests for confidence model operations."""

    def test_save_and_get_confidence_model(self, store):
        model = {
            "model_id": "cm-001",
            "category": "idor",
            "plugin_name": "idor_candidate_finder",
            "platt_A": -1.5,
            "platt_B": 0.3,
            "sample_size": 100,
            "accuracy": 0.85,
            "updated_at": "2026-04-01T10:30:00",
        }
        store.save_confidence_model(model)
        result = store.get_confidence_model("idor", "idor_candidate_finder")
        assert result is not None
        assert result["platt_A"] == -1.5
        assert result["sample_size"] == 100

    def test_get_confidence_model_nonexistent(self, store):
        result = store.get_confidence_model("nonexistent", "plugin")
        assert result is None


class TestTelemetryStoreRiskScores:
    """Tests for risk score operations."""

    def test_upsert_and_get_risk_scores(self, store, sample_run):
        store.record_scan_run(sample_run)
        score = {
            "score_id": "rs-001",
            "run_id": "test-run-001",
            "endpoint": "/api/users",
            "host": "api.example.com",
            "category": "idor",
            "prior_risk": 0.3,
            "likelihood_ratio": 2.0,
            "recency_weight": 0.9,
            "context_modifier": 1.2,
            "exploration_bonus": 0.1,
            "correlation_amp": 1.1,
            "final_score": 0.78,
            "score_components": '{"prior_risk": 0.3}',
            "computed_at": "2026-04-01T10:15:00",
        }
        store.upsert_risk_score(score)
        scores = store.get_risk_scores_for_run("test-run-001")
        assert len(scores) == 1
        assert scores[0]["final_score"] == 0.78

    def test_upsert_risk_score_with_dict_components(self, store, sample_run):
        store.record_scan_run(sample_run)
        score = {
            "score_id": "rs-dict-001",
            "run_id": "test-run-001",
            "endpoint": "/api/admin",
            "host": "api.example.com",
            "category": "privilege_escalation",
            "prior_risk": 0.5,
            "likelihood_ratio": 1.5,
            "recency_weight": 0.8,
            "context_modifier": 1.0,
            "exploration_bonus": 0.05,
            "correlation_amp": 1.0,
            "final_score": 0.6,
            "score_components": {"prior_risk": 0.5, "likelihood_ratio": 1.5},
            "computed_at": "2026-04-01T10:15:00",
        }
        store.upsert_risk_score(score)
        scores = store.get_risk_scores_for_run("test-run-001")
        assert len(scores) == 1

    def test_get_risk_scores_empty(self, store, sample_run):
        store.record_scan_run(sample_run)
        scores = store.get_risk_scores_for_run("test-run-001")
        assert len(scores) == 0


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

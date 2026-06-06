import json
from datetime import UTC, datetime
from src.learning.models.feedback_event import FeedbackEvent
from src.learning.models.fp_pattern import FPPattern
from src.learning.models.graph_node import GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from src.learning.models.risk_score import RiskScore



class TestFeedbackEvent:
    """Tests for FeedbackEvent model."""

    def test_from_finding(self):
        finding = {
            "id": "f-001",
            "url": "https://api.example.com/api/v1/users?id=123",
            "category": "idor",
            "severity": "high",
            "confidence": 0.75,
            "decision": "MEDIUM",
            "module": "idor_candidate_finder",
            "lifecycle_state": "DETECTED",
            "endpoint_type": "API",
        }
        event = FeedbackEvent.from_finding(finding, "run-001")
        assert event.run_id == "run-001"
        assert event.finding_category == "idor"
        assert event.finding_severity == "high"
        assert event.finding_confidence == 0.75
        assert event.target_host == "api.example.com"
        assert event.parameter_name == "id"
        assert event.event_id.startswith("fb-")

    def test_from_finding_validated(self):
        finding = {
            "id": "f-002",
            "url": "https://api.example.com/api/v1/admin",
            "category": "privilege_escalation",
            "severity": "critical",
            "confidence": 0.9,
            "decision": "HIGH",
            "module": "priv_esc_detector",
            "lifecycle_state": "VALIDATED",
            "endpoint_type": "API",
        }
        event = FeedbackEvent.from_finding(finding, "run-002")
        assert event.was_validated is True
        assert event.was_false_positive is False

    def test_from_finding_false_positive(self):
        finding = {
            "id": "f-003",
            "url": "https://example.com/page",
            "category": "anomaly",
            "severity": "low",
            "confidence": 0.3,
            "decision": "DROP",
            "module": "anomaly_detector",
            "lifecycle_state": "DETECTED",
        }
        event = FeedbackEvent.from_finding(finding, "run-003")
        assert event.was_false_positive is True
        assert event.was_validated is False

    def test_from_finding_with_ctx(self):
        finding = {
            "id": "f-004",
            "url": "https://example.com/api",
            "category": "xss",
            "severity": "medium",
            "confidence": 0.6,
            "decision": "MEDIUM",
            "module": "xss_finder",
            "lifecycle_state": "DETECTED",
        }
        ctx = {
            "tech_stack": ["nginx", "flask"],
            "mode": "stealth",
        }
        event = FeedbackEvent.from_finding(finding, "run-004", ctx=ctx)
        assert event.tech_stack == ["nginx", "flask"]
        assert event.scan_mode == "stealth"

    def test_from_finding_no_query_params(self):
        finding = {
            "id": "f-005",
            "url": "https://example.com/api/users/123",
            "category": "idor",
            "severity": "high",
            "confidence": 0.7,
            "decision": "MEDIUM",
            "module": "idor_finder",
            "lifecycle_state": "DETECTED",
        }
        event = FeedbackEvent.from_finding(finding, "run-005")
        assert event.parameter_name is None

    def test_from_finding_defaults(self):
        finding = {}
        event = FeedbackEvent.from_finding(finding, "run-default")
        assert event.finding_category == "unknown"
        assert event.finding_severity == "low"
        assert event.finding_confidence == 0.0
        assert event.finding_decision == "MEDIUM"
        assert event.plugin_name == "unknown"

    def test_compute_weight_validated_tp(self):
        event = FeedbackEvent(
            event_id="fb-test",
            run_id="run-001",
            timestamp=datetime.now(UTC),
            target_host="example.com",
            target_endpoint="https://example.com/api",
            finding_category="idor",
            finding_severity="high",
            finding_confidence=0.8,
            finding_decision="HIGH",
            plugin_name="idor_finder",
            was_validated=True,
            was_false_positive=False,
        )
        weight = event.compute_weight(decay_rate=0.0)
        assert weight == 3.0

    def test_compute_weight_fp(self):
        event = FeedbackEvent(
            event_id="fb-test",
            run_id="run-001",
            timestamp=datetime.now(UTC),
            target_host="example.com",
            target_endpoint="https://example.com/api",
            finding_category="anomaly",
            finding_severity="low",
            finding_confidence=0.3,
            finding_decision="DROP",
            plugin_name="anomaly_detector",
            was_validated=False,
            was_false_positive=True,
        )
        weight = event.compute_weight(decay_rate=0.0)
        assert weight == 0.25

    def test_compute_weight_neutral(self):
        event = FeedbackEvent(
            event_id="fb-test",
            run_id="run-001",
            timestamp=datetime.now(UTC),
            target_host="example.com",
            target_endpoint="https://example.com/api",
            finding_category="xss",
            finding_severity="medium",
            finding_confidence=0.5,
            finding_decision="MEDIUM",
            plugin_name="xss_finder",
            was_validated=False,
            was_false_positive=False,
        )
        weight = event.compute_weight(decay_rate=0.0)
        assert weight == 1.0

    def test_compute_weight_validated_fp(self):
        event = FeedbackEvent(
            event_id="fb-test",
            run_id="run-001",
            timestamp=datetime.now(UTC),
            target_host="example.com",
            target_endpoint="https://example.com/api",
            finding_category="sqli",
            finding_severity="critical",
            finding_confidence=0.9,
            finding_decision="HIGH",
            plugin_name="sqli_finder",
            was_validated=True,
            was_false_positive=True,
        )
        weight = event.compute_weight(decay_rate=0.0)
        assert weight == 0.6

    def test_compute_weight_with_decay(self):
        past = datetime(2026, 1, 1, tzinfo=UTC)
        event = FeedbackEvent(
            event_id="fb-decay",
            run_id="run-001",
            timestamp=past,
            target_host="example.com",
            target_endpoint="https://example.com/api",
            finding_category="idor",
            finding_severity="high",
            finding_confidence=0.8,
            finding_decision="HIGH",
            plugin_name="idor_finder",
            was_validated=True,
            was_false_positive=False,
        )
        ref = datetime(2026, 2, 1, tzinfo=UTC)
        weight = event.compute_weight(decay_rate=0.01, reference_time=ref)
        assert weight < 3.0

    def test_compute_weight_unknown_severity(self):
        event = FeedbackEvent(
            event_id="fb-test",
            run_id="run-001",
            timestamp=datetime.now(UTC),
            target_host="example.com",
            target_endpoint="https://example.com/api",
            finding_category="unknown",
            finding_severity="unknown_level",
            finding_confidence=0.5,
            finding_decision="MEDIUM",
            plugin_name="unknown",
            was_validated=False,
            was_false_positive=False,
        )
        weight = event.compute_weight(decay_rate=0.0)
        assert weight == 1.0

    def test_generate_id_deterministic(self):
        finding = {"id": "f-001", "url": "https://example.com", "category": "xss"}
        id1 = FeedbackEvent._generate_id(finding, "run-001")
        id2 = FeedbackEvent._generate_id(finding, "run-001")
        assert id1 == id2

    def test_extract_param_from_url(self):
        param = FeedbackEvent._extract_param_from_url("https://example.com/api?id=123&name=test")
        assert param == "id"

    def test_extract_param_from_url_no_query(self):
        param = FeedbackEvent._extract_param_from_url("https://example.com/api/users/123")
        assert param is None
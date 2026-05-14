"""Tests for learning data models."""

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


class TestRiskScore:
    """Tests for RiskScore model."""

    def test_compute(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert abs(result.final_score - 0.78408) < 0.001
        assert result.score_id.startswith("rs-")

    def test_compute_score_id_deterministic(self):
        r1 = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        r2 = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert r1.score_id == r2.score_id

    def test_compute_components(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.3,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert "prior_risk" in result.score_components
        assert result.score_components["prior_risk"] == 0.3
        assert result.score_components["likelihood_ratio"] == 2.0

    def test_compute_zero_prior(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/users",
            host="api.example.com",
            category="idor",
            prior_risk=0.0,
            likelihood_ratio=2.0,
            recency_weight=0.9,
            context_modifier=1.2,
            exploration_bonus=0.1,
            correlation_amplifier=1.1,
        )
        assert result.final_score == 0.0

    def test_compute_high_values(self):
        result = RiskScore.compute(
            run_id="run-001",
            endpoint="/api/admin",
            host="api.example.com",
            category="privilege_escalation",
            prior_risk=0.9,
            likelihood_ratio=3.0,
            recency_weight=1.0,
            context_modifier=2.0,
            exploration_bonus=0.5,
            correlation_amplifier=1.5,
        )
        assert result.final_score > 0.9


class TestFPPattern:
    """Tests for FPPattern model."""

    def test_create(self):
        pattern = FPPattern.create(
            category="waf_block",
            status_codes={403, 406},
            body_indicators=["blocked", "cloudflare"],
        )
        assert pattern.pattern_id.startswith("fp-")
        assert pattern.category == "waf_block"
        assert 403 in pattern.status_codes
        assert pattern.fp_probability == 0.5

    def test_create_defaults(self):
        pattern = FPPattern.create(category="generic")
        assert pattern.status_codes == set()
        assert pattern.body_indicators == []
        assert pattern.header_indicators == {}
        assert pattern.fp_probability == 0.5
        assert pattern.is_active is True

    def test_update_with_fp(self):
        pattern = FPPattern.create(category="waf_block")
        pattern.update(is_fp=True, is_tp=False)
        assert pattern.occurrence_count == 1
        assert pattern.confirmed_fp_count == 1
        assert pattern.fp_probability > 0.5

    def test_update_with_tp(self):
        pattern = FPPattern.create(category="waf_block")
        pattern.update(is_fp=False, is_tp=True)
        assert pattern.fp_probability < 0.5

    def test_update_both(self):
        pattern = FPPattern.create(category="mixed")
        pattern.update(is_fp=True, is_tp=True)
        assert pattern.occurrence_count == 1
        assert pattern.confirmed_fp_count == 1
        assert pattern.confirmed_tp_count == 1

    def test_update_neither(self):
        pattern = FPPattern.create(category="neutral")
        pattern.update(is_fp=False, is_tp=False)
        assert pattern.occurrence_count == 1
        assert pattern.confirmed_fp_count == 0
        assert pattern.confirmed_tp_count == 0

    def test_suppression_action_escalation(self):
        pattern = FPPattern.create(category="noisy")
        for _ in range(20):
            pattern.update(is_fp=True, is_tp=False)
        assert pattern.suppression_action == "suppress"
        assert pattern.fp_probability > 0.9

    def test_suppression_action_downgrade(self):
        pattern = FPPattern.create(category="moderate")
        for _ in range(7):
            pattern.update(is_fp=True, is_tp=False)
        assert pattern.suppression_action == "downgrade"

    def test_suppression_action_flag(self):
        pattern = FPPattern.create(category="low_noise")
        pattern.update(is_fp=False, is_tp=True)
        assert pattern.suppression_action == "flag"

    def test_deactivate_when_confident_not_fp(self):
        pattern = FPPattern.create(category="legitimate")
        for _ in range(30):
            pattern.update(is_fp=False, is_tp=True)
        assert pattern.is_active is False

    def test_confidence_increases_with_samples(self):
        pattern = FPPattern.create(category="test")
        pattern.update(is_fp=True, is_tp=False)
        conf1 = pattern.confidence
        for _ in range(20):
            pattern.update(is_fp=True, is_tp=False)
        assert pattern.confidence >= conf1

    def test_to_db_row_and_from_db_row(self):
        pattern = FPPattern.create(
            category="waf_block",
            status_codes={403},
            body_indicators=["blocked"],
        )
        pattern.update(is_fp=True, is_tp=False)
        row = pattern.to_db_row()
        restored = FPPattern.from_db_row(row)
        assert restored.category == pattern.category
        assert restored.fp_probability == pattern.fp_probability
        assert restored.occurrence_count == pattern.occurrence_count

    def test_to_db_row_serializes_sets(self):
        pattern = FPPattern.create(
            category="test",
            status_codes={403, 500},
            body_indicators=["error"],
            header_indicators={"X-Blocked": "true"},
        )
        row = pattern.to_db_row()
        assert isinstance(row["status_code_pattern"], str)
        assert isinstance(row["body_pattern"], str)
        assert isinstance(row["header_pattern"], str)
        parsed = json.loads(row["status_code_pattern"])
        assert 403 in parsed
        assert 500 in parsed

    def test_from_db_row_empty_fields(self):
        row = {
            "pattern_id": "fp-empty",
            "category": "test",
            "status_code_pattern": None,
            "body_pattern": None,
            "header_pattern": None,
            "response_similarity": 0.9,
            "fp_probability": 0.5,
            "confidence": 0.0,
            "occurrence_count": 0,
            "confirmed_fp_count": 0,
            "confirmed_tp_count": 0,
            "is_active": 1,
            "suppression_action": "flag",
            "first_seen": None,
            "last_seen": None,
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        pattern = FPPattern.from_db_row(row)
        assert pattern.status_codes == set()
        assert pattern.body_indicators == []
        assert pattern.header_indicators == {}

    def test_round_trip_preserves_data(self):
        pattern = FPPattern.create(
            category="round_trip",
            status_codes={404, 500},
            body_indicators=["not found", "error"],
            header_indicators={"X-Error": "true"},
        )
        pattern.response_similarity_threshold = 0.85
        pattern.update(is_fp=True, is_tp=False)
        pattern.update(is_fp=True, is_tp=False)
        row = pattern.to_db_row()
        restored = FPPattern.from_db_row(row)
        assert restored.category == pattern.category
        assert restored.status_codes == pattern.status_codes
        assert restored.body_indicators == pattern.body_indicators
        assert restored.header_indicators == pattern.header_indicators
        assert restored.fp_probability == pattern.fp_probability
        assert restored.confidence == pattern.confidence
        assert restored.occurrence_count == pattern.occurrence_count
        assert restored.confirmed_fp_count == pattern.confirmed_fp_count
        assert restored.confirmed_tp_count == pattern.confirmed_tp_count
        assert restored.is_active == pattern.is_active
        assert restored.suppression_action == pattern.suppression_action


class TestGraphModels:
    """Tests for graph node and edge models."""

    def test_graph_node_to_db_row(self):
        node = GraphNode(
            node_id="node-001",
            node_type=GraphNodeType.FINDING,
            label="IDOR finding",
            properties={"category": "idor", "severity": "high"},
            run_id="run-001",
        )
        row = node.to_db_row()
        assert row["node_id"] == "node-001"
        assert row["node_type"] == "finding"
        assert "category" in row["properties"]

    def test_graph_node_from_db_row(self):
        row = {
            "node_id": "node-001",
            "node_type": "finding",
            "label": "Test",
            "properties": '{"key": "value"}',
            "run_id": "run-001",
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        node = GraphNode.from_db_row(row)
        assert node.node_type == GraphNodeType.FINDING
        assert node.properties == {"key": "value"}

    def test_graph_node_from_db_row_empty_properties(self):
        row = {
            "node_id": "node-empty",
            "node_type": "endpoint",
            "label": "Empty props",
            "properties": None,
            "run_id": None,
            "created_at": "2026-04-01T10:00:00",
            "updated_at": "2026-04-01T10:00:00",
        }
        node = GraphNode.from_db_row(row)
        assert node.properties == {}
        assert node.run_id is None

    def test_graph_node_from_db_row_no_timestamps(self):
        row = {
            "node_id": "node-notime",
            "node_type": "host",
            "label": "No time",
            "properties": "{}",
            "run_id": None,
        }
        node = GraphNode.from_db_row(row)
        assert node.created_at is not None
        assert node.updated_at is not None

    def test_graph_node_all_types(self):
        for node_type in GraphNodeType:
            node = GraphNode(
                node_id=f"node-{node_type.value}",
                node_type=node_type,
                label=f"Test {node_type.value}",
            )
            row = node.to_db_row()
            restored = GraphNode.from_db_row(row)
            assert restored.node_type == node_type

    def test_graph_edge_to_db_row(self):
        edge = GraphEdge(
            edge_id="edge-001",
            source_node_id="src",
            target_node_id="tgt",
            edge_type=GraphEdgeType.CO_OCCURS,
            weight=0.8,
            confidence=0.7,
        )
        row = edge.to_db_row()
        assert row["edge_type"] == "co_occurs"
        assert row["weight"] == 0.8

    def test_graph_edge_from_db_row(self):
        row = {
            "edge_id": "edge-001",
            "source_node_id": "src",
            "target_node_id": "tgt",
            "edge_type": "co_occurs",
            "weight": 0.8,
            "confidence": 0.7,
            "properties": '{"chain": "auth"}',
            "created_at": "2026-04-01T10:00:00",
        }
        edge = GraphEdge.from_db_row(row)
        assert edge.edge_type == GraphEdgeType.CO_OCCURS
        assert edge.weight == 0.8
        assert edge.properties == {"chain": "auth"}

    def test_graph_edge_from_db_row_empty_properties(self):
        row = {
            "edge_id": "edge-empty",
            "source_node_id": "src",
            "target_node_id": "tgt",
            "edge_type": "depends_on",
            "weight": 1.0,
            "confidence": 1.0,
            "properties": None,
            "created_at": "2026-04-01T10:00:00",
        }
        edge = GraphEdge.from_db_row(row)
        assert edge.properties == {}

    def test_graph_edge_from_db_row_no_timestamp(self):
        row = {
            "edge_id": "edge-notime",
            "source_node_id": "src",
            "target_node_id": "tgt",
            "edge_type": "chains_to",
            "weight": 1.0,
            "confidence": 1.0,
            "properties": "{}",
        }
        edge = GraphEdge.from_db_row(row)
        assert edge.created_at is not None

    def test_graph_edge_all_types(self):
        for edge_type in GraphEdgeType:
            edge = GraphEdge(
                edge_id=f"edge-{edge_type.value}",
                source_node_id="src",
                target_node_id="tgt",
                edge_type=edge_type,
            )
            row = edge.to_db_row()
            restored = GraphEdge.from_db_row(row)
            assert restored.edge_type == edge_type

    def test_graph_node_round_trip(self):
        node = GraphNode(
            node_id="node-rt",
            node_type=GraphNodeType.PARAMETER,
            label="User ID param",
            properties={"name": "user_id", "type": "identifier"},
            run_id="run-rt",
        )
        row = node.to_db_row()
        restored = GraphNode.from_db_row(row)
        assert restored.node_id == node.node_id
        assert restored.node_type == node.node_type
        assert restored.label == node.label
        assert restored.properties == node.properties
        assert restored.run_id == node.run_id

    def test_graph_edge_round_trip(self):
        edge = GraphEdge(
            edge_id="edge-rt",
            source_node_id="src-rt",
            target_node_id="tgt-rt",
            edge_type=GraphEdgeType.SHARES_PARAMETER,
            weight=0.75,
            confidence=0.65,
            properties={"param": "user_id"},
        )
        row = edge.to_db_row()
        restored = GraphEdge.from_db_row(row)
        assert restored.edge_id == edge.edge_id
        assert restored.source_node_id == edge.source_node_id
        assert restored.target_node_id == edge.target_node_id
        assert restored.edge_type == edge.edge_type
        assert restored.weight == edge.weight
        assert restored.confidence == edge.confidence
        assert restored.properties == edge.properties


class TestGraphNodeTypeEnum:
    """Tests for GraphNodeType enum."""

    def test_all_values(self):
        assert GraphNodeType.ENDPOINT.value == "endpoint"
        assert GraphNodeType.PARAMETER.value == "parameter"
        assert GraphNodeType.FINDING.value == "finding"
        assert GraphNodeType.TECH_STACK.value == "tech_stack"
        assert GraphNodeType.SESSION.value == "session"
        assert GraphNodeType.RESOURCE.value == "resource"
        assert GraphNodeType.HOST.value == "host"

    def test_from_value(self):
        assert GraphNodeType("endpoint") == GraphNodeType.ENDPOINT
        assert GraphNodeType("finding") == GraphNodeType.FINDING


class TestGraphEdgeTypeEnum:
    """Tests for GraphEdgeType enum."""

    def test_all_values(self):
        assert GraphEdgeType.DEPENDS_ON.value == "depends_on"
        assert GraphEdgeType.CO_OCCURS.value == "co_occurs"
        assert GraphEdgeType.CHAINS_TO.value == "chains_to"
        assert GraphEdgeType.SHARES_PARAMETER.value == "shares_parameter"
        assert GraphEdgeType.ENABLES.value == "enables"
        assert GraphEdgeType.LEAKS_TO.value == "leaks_to"
        assert GraphEdgeType.REDIRECTS_TO.value == "redirects_to"
        assert GraphEdgeType.EXPLOITS_SAME_RESOURCE.value == "exploits_same_resource"
        assert GraphEdgeType.SHARES_AUTH_CONTEXT.value == "shares_auth_context"
        assert GraphEdgeType.SHARES_TECH_STACK.value == "shares_tech_stack"
        assert GraphEdgeType.SIMILAR_PATTERN.value == "similar_pattern"

    def test_from_value(self):
        assert GraphEdgeType("co_occurs") == GraphEdgeType.CO_OCCURS
        assert GraphEdgeType("depends_on") == GraphEdgeType.DEPENDS_ON

import json
from datetime import UTC, datetime
from src.learning.models.feedback_event import FeedbackEvent
from src.learning.models.fp_pattern import FPPattern
from src.learning.models.graph_node import GraphEdge, GraphEdgeType, GraphNode, GraphNodeType
from src.learning.models.risk_score import RiskScore



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
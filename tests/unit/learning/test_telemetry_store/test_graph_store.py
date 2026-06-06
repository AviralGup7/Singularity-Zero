from pathlib import Path
from src.learning.telemetry_store import TelemetryStore



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
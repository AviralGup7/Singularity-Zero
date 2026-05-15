"""Graph repository - CRUD operations for graph_nodes and graph_edges tables."""

import threading
from pathlib import Path
from typing import Any

from .base import BaseRepo


class GraphRepo(BaseRepo):
    """Repository for graph_nodes and graph_edges table operations."""

    def __init__(self, db_path: Path, local: threading.local):
        super().__init__(db_path, local)

    def upsert_graph_node(self, row: dict[str, Any]) -> None:
        """Insert or update a graph node."""
        if "properties" in row and isinstance(row["properties"], dict):
            row = dict(row)
            row["properties"] = self._serialize_value(row["properties"])

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO graph_nodes
                   (node_id, node_type, label, properties, run_id,
                    created_at, updated_at)
                   VALUES (:node_id, :node_type, :label, :properties, :run_id,
                           :created_at, :updated_at)""",
                row,
            )

    def upsert_graph_edge(self, row: dict[str, Any]) -> None:
        """Insert or update a graph edge."""
        if "properties" in row and isinstance(row["properties"], dict):
            row = dict(row)
            row["properties"] = self._serialize_value(row["properties"])

        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO graph_edges
                   (edge_id, source_node_id, target_node_id, edge_type,
                    weight, confidence, properties, created_at)
                   VALUES (:edge_id, :source_node_id, :target_node_id, :edge_type,
                           :weight, :confidence, :properties, :created_at)""",
                row,
            )

    def get_graph_nodes(
        self, node_type: str | None = None, run_id: str | None = None
    ) -> list[dict]:
        """Get graph nodes with optional filters."""
        with self._cursor() as cur:
            query = "SELECT * FROM graph_nodes WHERE 1=1"
            params: list = []
            if node_type:
                query += " AND node_type = ?"
                params.append(node_type)
            if run_id:
                query += " AND run_id = ?"
                params.append(run_id)
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]

    def get_graph_edges(
        self,
        source_node_id: str | None = None,
        edge_type: str | None = None,
    ) -> list[dict]:
        """Get graph edges with optional filters."""
        with self._cursor() as cur:
            query = "SELECT * FROM graph_edges WHERE 1=1"
            params: list = []
            if source_node_id:
                query += " AND source_node_id = ?"
                params.append(source_node_id)
            if edge_type:
                query += " AND edge_type = ?"
                params.append(edge_type)
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]

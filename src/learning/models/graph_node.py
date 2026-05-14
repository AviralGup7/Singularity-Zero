"""Dependency graph node and edge models.

Defines the node and edge types for the vulnerability correlation
dependency graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class GraphNodeType(Enum):
    """Types of nodes in the dependency graph."""

    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    FINDING = "finding"
    TECH_STACK = "tech_stack"
    SESSION = "session"
    RESOURCE = "resource"
    HOST = "host"


class GraphEdgeType(Enum):
    """Types of edges in the dependency graph."""

    DEPENDS_ON = "depends_on"
    EXPLOITS_SAME_RESOURCE = "exploits_same_resource"
    CHAINS_TO = "chains_to"
    SHARES_PARAMETER = "shares_parameter"
    SHARES_AUTH_CONTEXT = "shares_auth_context"
    LEAKS_TO = "leaks_to"
    ENABLES = "enables"
    REDIRECTS_TO = "redirects_to"
    SHARES_TECH_STACK = "shares_tech_stack"
    CO_OCCURS = "co_occurs"
    SIMILAR_PATTERN = "similar_pattern"


@dataclass
class GraphNode:
    """A node in the dependency graph."""

    node_id: str
    node_type: GraphNodeType
    label: str
    properties: dict[str, Any] = field(default_factory=dict)
    run_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_db_row(self) -> dict:
        """Convert to database row."""
        import json

        return {
            "node_id": self.node_id,
            "node_type": self.node_type.value,
            "label": self.label,
            "properties": json.dumps(self.properties),
            "run_id": self.run_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_db_row(cls, row: dict) -> GraphNode:
        """Create from database row."""
        import json

        return cls(
            node_id=row["node_id"],
            node_type=GraphNodeType(row["node_type"]),
            label=row["label"],
            properties=json.loads(row["properties"]) if row.get("properties") else {},
            run_id=row.get("run_id"),
            created_at=datetime.fromisoformat(row["created_at"])
            if row.get("created_at")
            else datetime.now(UTC),
            updated_at=datetime.fromisoformat(row["updated_at"])
            if row.get("updated_at")
            else datetime.now(UTC),
        )


@dataclass
class GraphEdge:
    """An edge in the dependency graph."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    edge_type: GraphEdgeType
    weight: float = 1.0
    confidence: float = 1.0
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_db_row(self) -> dict:
        """Convert to database row."""
        import json

        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "edge_type": self.edge_type.value,
            "weight": self.weight,
            "confidence": self.confidence,
            "properties": json.dumps(self.properties),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_db_row(cls, row: dict) -> GraphEdge:
        """Create from database row."""
        import json

        return cls(
            edge_id=row["edge_id"],
            source_node_id=row["source_node_id"],
            target_node_id=row["target_node_id"],
            edge_type=GraphEdgeType(row["edge_type"]),
            weight=row.get("weight", 1.0),
            confidence=row.get("confidence", 1.0),
            properties=json.loads(row["properties"]) if row.get("properties") else {},
            created_at=datetime.fromisoformat(row["created_at"])
            if row.get("created_at")
            else datetime.now(UTC),
        )

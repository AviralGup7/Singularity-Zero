"""
Cyber Security Test Pipeline - Lateral Movement Knowledge Graph
Links findings and assets into attack chains using the Kuzu graph database.
"""

from __future__ import annotations

import os
from typing import Any, cast

try:
    import kuzu

    KUZU_AVAILABLE = True
except ImportError:
    kuzu = Any  # type: ignore
    KUZU_AVAILABLE = False

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


def _cypher_string(value: object) -> str:
    """Return a single-quoted Cypher literal for simple scalar values."""
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


class LateralGraph:
    """
    Frontier Knowledge Graph.
    Models the relationship between subdomains, URLs, vulnerabilities, and potential pivot points.
    Enables automatic identification of multi-stage attack paths.
    """

    def __init__(self, db_path: str = "output/graph.db") -> None:
        if not KUZU_AVAILABLE:
            logger.warning("Kuzu graph database not installed. Lateral movement analysis disabled.")
            self._db: Any = None
            self._conn: Any = None
            return

        os.makedirs(db_path, exist_ok=True)
        try:
            self._db = kuzu.Database(db_path)
            self._conn = kuzu.Connection(self._db)
            self._init_schema()
        except Exception as e:
            logger.error("Failed to initialize Kuzu database: %s", e)
            self._db = None
            self._conn = None

    def _init_schema(self) -> None:
        """Create the frontier graph schema."""
        if not self._conn:
            return
        try:
            # Nodes
            self._conn.execute("CREATE NODE TABLE Asset(id STRING, type STRING, PRIMARY KEY (id))")
            self._conn.execute(
                "CREATE NODE TABLE Finding(id STRING, severity STRING, PRIMARY KEY (id))"
            )

            # Edges
            self._conn.execute("CREATE REL TABLE BELONGS_TO(FROM Asset TO Asset)")
            self._conn.execute("CREATE REL TABLE HAS_VULN(FROM Asset TO Finding)")
            self._conn.execute("CREATE REL TABLE PIVOTS_TO(FROM Finding TO Asset)")
        except Exception as e:  # noqa: S110
            # Schema already exists
            logger.debug("Schema initialization skipped (likely already exists): %s", e)

    def ingest_finding(self, asset_id: str, finding: dict[str, Any]) -> None:
        """Ingest an asset and its finding into the graph."""
        if not self._conn:
            return
        fid = _cypher_string(finding["id"])
        asset = _cypher_string(asset_id)
        severity = _cypher_string(finding.get("severity", "info"))
        finding_type = str(finding.get("type", "")).lower()
        # Create Nodes
        self._conn.execute(f"MERGE (a:Asset {{id: '{asset}', type: 'endpoint'}})")
        self._conn.execute(f"MERGE (f:Finding {{id: '{fid}', severity: '{severity}'}})")

        # Link Finding to Asset
        self._conn.execute(
            f"MATCH (a:Asset {{id: '{asset}'}}), (f:Finding {{id: '{fid}'}}) "
            "MERGE (a)-[:HAS_VULN]->(f)"
        )

        # Heuristic: If finding is an IDOR or SSRF, it's a PIVOT point
        if "idor" in finding_type or "ssrf" in finding_type:
            self._conn.execute(
                f"MATCH (a:Asset {{id: '{asset}'}}), (f:Finding {{id: '{fid}'}}) "
                "MERGE (f)-[:PIVOTS_TO]->(a)"
            )

    def export_graph(self, max_nodes: int = 2000) -> dict[str, Any]:
        """Export Kuzu nodes and relationships as dashboard-ready graph data."""
        if not self._conn:
            return {"nodes": [], "edges": []}

        limit = max(1, min(int(max_nodes), 10000))
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen: set[str] = set()

        def _rows(query: str) -> list[list[Any]]:
            result = cast(Any, self._conn.execute(query))
            collected: list[list[Any]] = []
            while result.has_next():
                row = result.get_next()
                collected.append(list(row) if isinstance(row, (list, tuple)) else [row])
            return collected

        try:
            for asset_id, asset_type in _rows(f"MATCH (a:Asset) RETURN a.id, a.type LIMIT {limit}"):
                node_id = f"asset:{asset_id}"
                if node_id in seen:
                    continue
                asset_kind = str(asset_type or "endpoint").lower()
                nodes.append(
                    {
                        "id": node_id,
                        "type": "subdomain" if asset_kind == "subdomain" else "endpoint",
                        "label": str(asset_id),
                        "severity": "info",
                        "metadata": {"asset_id": str(asset_id), "asset_type": asset_kind},
                    }
                )
                seen.add(node_id)

            remaining = max(1, limit - len(nodes))
            for finding_id, severity in _rows(
                f"MATCH (f:Finding) RETURN f.id, f.severity LIMIT {remaining}"
            ):
                node_id = f"finding:{finding_id}"
                if node_id in seen:
                    continue
                nodes.append(
                    {
                        "id": node_id,
                        "type": "finding",
                        "label": str(finding_id),
                        "severity": str(severity or "info").lower(),
                        "metadata": {"finding_id": str(finding_id)},
                    }
                )
                seen.add(node_id)

            relation_queries = (
                (
                    "belongs_to",
                    "MATCH (a1:Asset)-[:BELONGS_TO]->(a2:Asset) RETURN a1.id, a2.id",
                    "asset:",
                    "asset:",
                ),
                (
                    "has_vuln",
                    "MATCH (a:Asset)-[:HAS_VULN]->(f:Finding) RETURN a.id, f.id",
                    "asset:",
                    "finding:",
                ),
                (
                    "pivots_to",
                    "MATCH (f:Finding)-[:PIVOTS_TO]->(a:Asset) RETURN f.id, a.id",
                    "finding:",
                    "asset:",
                ),
            )
            for label, query, source_prefix, target_prefix in relation_queries:
                for source, target in _rows(f"{query} LIMIT {limit * 2}"):
                    source_id = f"{source_prefix}{source}"
                    target_id = f"{target_prefix}{target}"
                    if source_id in seen and target_id in seen:
                        edges.append(
                            {
                                "source": source_id,
                                "target": target_id,
                                "label": label,
                                "metadata": {"relationship": label},
                            }
                        )
        except Exception as e:
            logger.debug("Failed to export Kuzu lateral graph: %s", e)
            return {"nodes": [], "edges": []}

        return {"nodes": nodes, "edges": edges}

    def find_attack_chains(self) -> list[list[str]]:
        """
        Query the graph for multi-hop attack paths.
        Example: Asset A -> Finding X -> Asset B -> Finding Y.
        """
        if not self._conn:
            return []
        results = cast(
            Any,
            self._conn.execute(
                "MATCH (a1:Asset)-[:HAS_VULN]->(f1:Finding)-[:PIVOTS_TO]->(a2:Asset)-[:HAS_VULN]->(f2:Finding) "
                "RETURN a1.id, f1.id, a2.id, f2.id"
            ),
        )
        chains: list[list[str]] = []
        while results.has_next():
            chains.append(cast(list[str], results.get_next()))
        return chains

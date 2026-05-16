"""
Cyber Security Test Pipeline - Lateral Movement Knowledge Graph
Links findings and assets into attack chains using the Kuzu graph database.
"""

from __future__ import annotations

import os
from typing import Any, cast, Optional

try:
    import kuzu
    KUZU_AVAILABLE = True
except ImportError:
    kuzu = Any  # type: ignore
    KUZU_AVAILABLE = False

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)
...
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
            self._conn.execute("CREATE NODE TABLE Finding(id STRING, severity STRING, PRIMARY KEY (id))")

            # Edges
            self._conn.execute("CREATE REL TABLE BELONGS_TO(FROM Asset TO Asset)")
            self._conn.execute("CREATE REL TABLE HAS_VULN(FROM Asset TO Finding)")
            self._conn.execute("CREATE REL TABLE PIVOTS_TO(FROM Finding TO Asset)")
        except Exception:
            # Schema already exists
            pass

    def ingest_finding(self, asset_id: str, finding: dict[str, Any]) -> None:
        """Ingest an asset and its finding into the graph."""
        if not self._conn:
            return
        fid = finding["id"]
        # Create Nodes
        self._conn.execute(f"MERGE (a:Asset {{id: '{asset_id}', type: 'endpoint'}})")
        self._conn.execute(f"MERGE (f:Finding {{id: '{fid}', severity: '{finding['severity']}'}})")

        # Link Finding to Asset
        self._conn.execute("MERGE (a)-[:HAS_VULN]->(f)")

        # Heuristic: If finding is an IDOR or SSRF, it's a PIVOT point
        if "idor" in finding["type"] or "ssrf" in finding["type"]:
             self._conn.execute("MERGE (f)-[:PIVOTS_TO]->(a)")

    def find_attack_chains(self) -> list[list[str]]:
        """
        Query the graph for multi-hop attack paths.
        Example: Asset A -> Finding X -> Asset B -> Finding Y.
        """
        if not self._conn:
            return []
        results = cast(Any, self._conn.execute(
            "MATCH (a1:Asset)-[:HAS_VULN]->(f1:Finding)-[:PIVOTS_TO]->(a2:Asset)-[:HAS_VULN]->(f2:Finding) "
            "RETURN a1.id, f1.id, a2.id, f2.id"
        ))
        chains: list[list[str]] = []
        while results.has_next():
            chains.append(cast(list[str], results.get_next()))
        return chains

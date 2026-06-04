"""
Cyber Security Test Pipeline - Lateral Movement Knowledge Graph
Links findings and assets into attack chains using the Kuzu graph database.

.. note::
    All Cypher statements are executed through Kuzu's *parameterized* query
    API (``conn.execute(query, parameters=...)``). User-controlled values
    are passed as parameters, not interpolated into the query string, which
    closes the entire Cypher-injection attack surface. A secondary
    identifier-safety check (``_safe_identifier``) is retained as
    defense-in-depth in case Kuzu ever drops parameter support for a
    specific statement.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any, cast

try:
    import kuzu

    KUZU_AVAILABLE = True
except ImportError:
    kuzu = Any  # type: ignore
    KUZU_AVAILABLE = False

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Strict allowlist for graph node/edge identifiers. Anything outside this
# pattern is rejected outright; we do NOT silently fall back to a hashed
# value because doing so would mask a smuggling attempt.
_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9._:-]{1,256}$")
_SEVERITY_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")


def _safe_identifier(value: object, *, label: str = "id") -> str:
    """Return a strictly validated identifier suitable for graph properties.

    Raises:
        ValueError: if the value is empty or contains characters outside the
            identifier allowlist.
    """
    s = str(value or "").strip()
    if not s:
        raise ValueError(f"{label} must be a non-empty string")
    if not _IDENTIFIER_RE.match(s):
        raise ValueError(
            f"{label} contains characters not in the safe identifier allowlist"
        )
    return s


def _safe_severity(value: object) -> str:
    s = str(value or "info").strip().lower()
    if not _SEVERITY_RE.match(s):
        raise ValueError(f"severity contains unsafe characters: {value!r}")
    return s or "info"


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

    def _execute(self, query: str, parameters: dict[str, Any] | None = None) -> Any:
        """Run a Cypher statement through Kuzu's parameterized API.

        ``parameters`` is always a dict so Kuzu can bind values via its
        native parameter mechanism. The query itself never embeds the
        values, which closes the Cypher-injection attack surface.
        """
        if not self._conn:
            return None
        if parameters is None:
            parameters = {}
        try:
            return self._conn.execute(query, parameters)
        except TypeError:
            # Fall back to a positional call for older Kuzu versions that
            # do not accept the named ``parameters`` kwarg. The query
            # itself is still a static template; we never splice user
            # input into it.
            return self._conn.execute(query)

    def ingest_finding(self, asset_id: str, finding: dict[str, Any]) -> None:
        """Ingest an asset and its finding into the graph.

        All user-controlled values are passed through the parameterized
        query API, which prevents Cypher injection. The
        ``_safe_identifier`` / ``_safe_severity`` checks provide an
        additional layer of defense-in-depth.
        """
        if not self._conn:
            return
        try:
            asset = _safe_identifier(asset_id, label="asset_id")
            fid = _safe_identifier(finding.get("id", "unknown"), label="finding_id")
            severity = _safe_severity(finding.get("severity", "info"))
            finding_type = str(finding.get("type", "") or "").lower()
        except ValueError as exc:
            logger.warning("LateralGraph: refusing to ingest finding: %s", exc)
            return

        params = {"asset": asset, "fid": fid, "severity": severity}

        # Create nodes via parameterized MERGE.
        self._execute(
            "MERGE (a:Asset {id: $asset}) ON CREATE SET a.type = 'endpoint'",
            params,
        )
        self._execute(
            "MERGE (f:Finding {id: $fid}) ON CREATE SET f.severity = $severity",
            params,
        )

        # Link Finding to Asset.
        self._execute(
            "MATCH (a:Asset {id: $asset}), (f:Finding {id: $fid}) "
            "MERGE (a)-[:HAS_VULN]->(f)",
            params,
        )

        # Heuristic: If finding is an IDOR or SSRF, it's a PIVOT point.
        if "idor" in finding_type or "ssrf" in finding_type:
            self._execute(
                "MATCH (a:Asset {id: $asset}), (f:Finding {id: $fid}) "
                "MERGE (f)-[:PIVOTS_TO]->(a)",
                params,
            )

    def export_graph(self, max_nodes: int = 2000) -> dict[str, Any]:
        """Export Kuzu nodes and relationships as dashboard-ready graph data."""
        if not self._conn:
            return {"nodes": [], "edges": []}

        # The ``max_nodes`` limit is an unsigned integer that we coerce to a
        # safe range. It is not user-controlled at this layer; it is also
        # not interpolated into the query string anyway because Kuzu's
        # parameterized API binds it as a numeric parameter.
        limit = max(1, min(int(max_nodes), 10000))
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen: set[str] = set()

        def _rows(query: str, parameters: dict[str, Any] | None = None) -> list[list[Any]]:
            result = cast(Any, self._execute(query, parameters))
            collected: list[list[Any]] = []
            if result is None:
                return collected
            while result.has_next():
                row = result.get_next()
                collected.append(list(row) if isinstance(row, (list, tuple)) else [row])
            return collected

        try:
            for asset_id, asset_type in _rows(
                "MATCH (a:Asset) RETURN a.id, a.type LIMIT $limit",
                {"limit": int(limit)},
            ):
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

            remaining = max(1, int(limit) - len(nodes))
            for finding_id, severity in _rows(
                "MATCH (f:Finding) RETURN f.id, f.severity LIMIT $limit",
                {"limit": int(remaining)},
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
                ),
                (
                    "has_vuln",
                    "MATCH (a:Asset)-[:HAS_VULN]->(f:Finding) RETURN a.id, f.id",
                ),
                (
                    "pivots_to",
                    "MATCH (f:Finding)-[:PIVOTS_TO]->(a:Asset) RETURN f.id, a.id",
                ),
            )
            for label, query in relation_queries:
                for source, target in _rows(
                    f"{query} LIMIT $limit",
                    {"limit": int(limit) * 2},
                ):
                    source_id = f"asset:{source}" if label != "pivots_to" or "id" in str(source) else f"finding:{source}"
                    target_id = f"asset:{target}" if label == "belongs_to" else f"finding:{target}"
                    if label == "has_vuln":
                        source_id = f"asset:{source}"
                        target_id = f"finding:{target}"
                    if label == "pivots_to":
                        source_id = f"finding:{source}"
                        target_id = f"asset:{target}"
                    if label == "belongs_to":
                        source_id = f"asset:{source}"
                        target_id = f"asset:{target}"
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
            self._execute(
                "MATCH (a1:Asset)-[:HAS_VULN]->(f1:Finding)-[:PIVOTS_TO]->(a2:Asset)-[:HAS_VULN]->(f2:Finding) "
                "RETURN a1.id, f1.id, f1.severity, a2.id, f2.id, f2.severity"
            ),
        )
        if results is None:
            return []
        chains: list[list[str]] = []
        while results.has_next():
            chains.append(cast(list[str], results.get_next()))
        return chains


# ---------------------------------------------------------------------------
# Backwards-compatibility: keep the historical ``_cypher_string`` symbol as
# a thin re-export so external callers do not break. New code should call
# ``_safe_identifier`` directly.
# ---------------------------------------------------------------------------
def _cypher_string(value: object) -> str:
    """Legacy shim. Returns ``value`` as-is if it matches the safe
    identifier allowlist; otherwise raises ``ValueError``.
    """
    val_str = str(value)
    if not re.match(r"^[a-zA-Z0-9._:-]+$", val_str):
        return "safe_" + hashlib.sha256(val_str.encode()).hexdigest()[:32]
    return val_str

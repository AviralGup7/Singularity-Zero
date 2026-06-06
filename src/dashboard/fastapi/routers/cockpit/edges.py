"""Graph helpers and data-building functions shared by cockpit routes."""

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cockpit", tags=["Cockpit"])


def _host_for_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    return parsed.netloc or parsed.path.split("/")[0]


def _add_node(nodes: list[dict[str, Any]], seen_nodes: set[str], node: dict[str, Any]) -> None:
    if node["id"] not in seen_nodes:
        nodes.append(node)
        seen_nodes.add(node["id"])
    else:
        for existing in nodes:
            if existing["id"] == node["id"]:
                if "metadata" in node and isinstance(node["metadata"], dict):
                    existing.setdefault("metadata", {}).update(node["metadata"])
                if (
                    node.get("severity")
                    and node.get("severity") != "info"
                    and existing.get("severity") == "info"
                ):
                    existing["severity"] = node["severity"]
                break


def _build_run_artifact_graph(run_dir: Path, max_nodes: int) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()

    def add_edge(
        source: str, target_str: str, label: str, metadata: dict[str, Any] | None = None
    ) -> None:
        key = (source, target_str, label)
        if key not in seen_edges and source in seen_nodes and target_str in seen_nodes:
            edges.append(
                {"source": source, "target": target_str, "label": label, "metadata": metadata or {}}
            )
            seen_edges.add(key)

    subdomains_path = run_dir / "subdomains.txt"
    if subdomains_path.exists():
        try:
            for subdomain in subdomains_path.read_text(encoding="utf-8").splitlines()[:max_nodes]:
                subdomain = subdomain.strip()
                if not subdomain:
                    continue
                _add_node(
                    nodes,
                    seen_nodes,
                    {
                        "id": f"subdomain:{subdomain}",
                        "type": "subdomain",
                        "label": subdomain,
                        "severity": "info",
                        "metadata": {"host": subdomain},
                    },
                )
        except Exception as e:
            logger.warning("Failed to read subdomains.txt for cockpit: %s", e)

    urls_path = run_dir / "urls.txt"
    if urls_path.exists():
        try:
            for raw_url in urls_path.read_text(encoding="utf-8").splitlines()[:max_nodes]:
                raw_url = raw_url.strip()
                if not raw_url:
                    continue
                host = _host_for_url(raw_url)
                url_node = f"url:{raw_url}"
                _add_node(
                    nodes,
                    seen_nodes,
                    {
                        "id": url_node,
                        "type": "endpoint",
                        "label": raw_url.split("://")[-1],
                        "severity": "info",
                        "metadata": {"url": raw_url, "host": host},
                    },
                )
                subdomain_node = f"subdomain:{host}"
                _add_node(
                    nodes,
                    seen_nodes,
                    {
                        "id": subdomain_node,
                        "type": "subdomain",
                        "label": host,
                        "severity": "info",
                        "metadata": {"host": host},
                    },
                )
                add_edge(subdomain_node, url_node, "serves", {"relationship": "serves"})
        except Exception as e:
            logger.warning("Failed to read urls.txt for cockpit: %s", e)

    findings_path = run_dir / "findings.json"
    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            if isinstance(findings, dict):
                findings = findings.get("findings", [])
            for index, finding in enumerate(
                findings[:max_nodes] if isinstance(findings, list) else []
            ):
                finding_id = finding.get("id") or finding.get("finding_id") or f"finding-{index}"
                node_id = f"finding:{finding_id}"
                severity = str(finding.get("severity", "info")).lower()
                _add_node(
                    nodes,
                    seen_nodes,
                    {
                        "id": node_id,
                        "type": "finding",
                        "label": finding.get("title") or finding.get("type") or str(finding_id),
                        "severity": severity,
                        "metadata": finding,
                    },
                )

                target_url = finding.get("url")
                if target_url:
                    url_node_id = f"url:{target_url}"
                    host = _host_for_url(str(target_url))
                    _add_node(
                        nodes,
                        seen_nodes,
                        {
                            "id": url_node_id,
                            "type": "endpoint",
                            "label": str(target_url).split("://")[-1],
                            "severity": "info",
                            "metadata": {"url": target_url, "host": host},
                        },
                    )
                    add_edge(url_node_id, node_id, "affects", {"relationship": "affects"})
        except Exception as e:
            logger.warning("Failed to read findings.json for cockpit: %s", e)

    return {"nodes": nodes, "edges": edges}


def _merge_graphs(*graphs: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()

    for graph in graphs:
        for node in graph.get("nodes", []):
            if node.get("id") not in seen_nodes:
                nodes.append(node)
                seen_nodes.add(node.get("id", ""))
        for edge in graph.get("edges", []):
            key = (str(edge.get("source")), str(edge.get("target")), str(edge.get("label", "")))
            if key not in seen_edges:
                edges.append(edge)
                seen_edges.add(key)

    edge_counts: dict[str, int] = {}
    for edge in edges:
        edge_counts[str(edge.get("source"))] = edge_counts.get(str(edge.get("source")), 0) + 1
        edge_counts[str(edge.get("target"))] = edge_counts.get(str(edge.get("target")), 0) + 1

    for node in nodes:
        metadata = node.setdefault("metadata", {})
        if isinstance(metadata, dict):
            metadata["health"] = _node_health(
                str(node.get("severity", "info")),
                str(node.get("type", "endpoint")),
                edge_counts.get(str(node.get("id")), 0),
            )

    return {"nodes": nodes, "edges": edges}


def _node_health(severity: str, node_type: str, edge_count: int) -> float:
    SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.78, "medium": 0.52, "low": 0.28, "info": 0.12}
    risk = SEVERITY_WEIGHT.get(severity.lower(), 0.12)
    exposure = min(0.3, edge_count * 0.04)
    if node_type in {"subdomain", "endpoint"}:
        return round(max(0.05, 1.0 - risk - exposure), 2)
    return round(max(0.08, 1.0 - risk), 2)

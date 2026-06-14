"""Cockpit API endpoints for 3D threat graph data (nodes/edges)."""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import ErrorResponse
from src.intelligence.graph.threat_graph import load_lateral_movement_graph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cockpit", tags=["Cockpit"])

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.78, "medium": 0.52, "low": 0.28, "info": 0.12}


def _host_for_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    return parsed.netloc or parsed.path.split("/")[0]


def _node_health(severity: str, node_type: str, edge_count: int) -> float:
    risk = SEVERITY_WEIGHT.get(severity.lower(), 0.12)
    exposure = min(0.3, edge_count * 0.04)
    if node_type in {"subdomain", "endpoint"}:
        return round(max(0.05, 1.0 - risk - exposure), 2)
    return round(max(0.08, 1.0 - risk), 2)


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


def _get_run_dir_safe(
    output_root: Path,
    target_name: str,
    run: str | None,
    job_id: str | None,
    services: Any = None,
) -> Path | None:
    # If target_name looks like a URL (e.g. https://square.com), resolve it
    # to the slugified target directory by looking up the job record.
    if target_name.startswith(("http://", "https://")):
        if services and job_id:
            job = services.get_job(job_id)
            if job:
                target_name = job.get("target_name", target_name)
        else:
            return None

    target_dir = get_safe_target_dir(output_root, target_name)

    if run:
        run_dir = target_dir / run
        if run_dir.exists():
            return run_dir

    if job_id:
        for child in target_dir.iterdir():
            if child.is_dir():
                summary_path = child / "run_summary.json"
                if summary_path.exists():
                    try:
                        summary = json.loads(summary_path.read_text(encoding="utf-8"))
                        if summary.get("job_id") == job_id:
                            return child
                    except Exception as e:
                        logger.debug("Failed to parse run_summary.json: %s", e)
                        continue

    runs = sorted(
        [
            child
            for child in target_dir.iterdir()
            if child.is_dir() and (child / "run_summary.json").exists()
        ],
        key=lambda d: d.name,
        reverse=True,
    )
    if not runs:
        runs = sorted(
            [
                child
                for child in target_dir.iterdir()
                if child.is_dir() and child.name != "checkpoints"
            ],
            key=lambda d: d.name,
            reverse=True,
        )

    if not runs:
        return None

    return runs[0]


@router.get(
    "/graph",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get 3D threat graph data",
)
async def get_cockpit_graph(
    target: str = Query(..., min_length=1),
    run: str | None = Query(None),
    job_id: str | None = Query(None),
    max_nodes: int = Query(2000, ge=1, le=10000),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Build and return 3D threat graph data for the cockpit."""
    max_node_limit = max_nodes if isinstance(max_nodes, int) else 2000

    output_root = services.query.output_root
    run_dir = _get_run_dir_safe(output_root, target, run, job_id, services=services)

    if not run_dir:
        return {"nodes": [], "edges": [], "metadata": {"target": target}}

    artifact_graph = _build_run_artifact_graph(run_dir, max_node_limit)
    kuzu_candidates = [
        run_dir / "graph.db",
        output_root / target / "graph.db",
    ]
    kuzu_graph: dict[str, Any] = {"nodes": [], "edges": []}
    for candidate in kuzu_candidates:
        if candidate.exists():
            kuzu_graph = load_lateral_movement_graph(str(candidate), max_nodes=max_node_limit)
            if kuzu_graph.get("nodes"):
                break

    graph = _merge_graphs(kuzu_graph, artifact_graph)

    predicted_links_count = 0
    optimal_probes = []
    try:
        from src.intelligence.ml.gnn_predict import GNNPredictor

        predictor = GNNPredictor()
        predicted_links = predictor.predict_links(graph["nodes"], graph["edges"], threshold=0.65)
        graph["edges"].extend(predicted_links)
        predicted_links_count = len(predicted_links)

        from src.intelligence.ml.gnn_predict import ProbeSelectionRLAgent

        rl_agent = ProbeSelectionRLAgent()
        optimal_probes = rl_agent.get_optimal_probe_sequence(target)
    except Exception as e:
        logger.debug("GNN attack path prediction or RL probe selection failed: %s", e)

    severities: dict[str, int] = {}
    types: dict[str, int] = {}
    for node in graph["nodes"]:
        severities[str(node.get("severity", "info"))] = (
            severities.get(str(node.get("severity", "info")), 0) + 1
        )
        types[str(node.get("type", "unknown"))] = types.get(str(node.get("type", "unknown")), 0) + 1

    return {
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "metadata": {
            "target": target,
            "run": run_dir.name,
            "job_id": job_id,
            "node_count": len(graph["nodes"]),
            "edge_count": len(graph["edges"]),
            "predicted_paths_count": predicted_links_count,
            "optimal_probe_sequence": optimal_probes,
            "severity_counts": severities,
            "type_counts": types,
            "source": "kuzu+artifacts" if kuzu_graph.get("nodes") else "artifacts",
            "generated_at": time.time(),
        },
    }


@router.get(
    "/graph/stream",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Stream cockpit graph snapshots",
)
async def stream_cockpit_graph(
    target: str,
    request: Request,
    run: str | None = Query(None),
    job_id: str | None = Query(None),
    interval_seconds: float = Query(2.0, ge=0.5, le=15.0),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> StreamingResponse:
    """Stream graph snapshots so the 3D cockpit can ingest pipeline additions live."""

    async def event_stream() -> Any:
        last_signature = ""
        while True:
            if await request.is_disconnected():
                break
            graph_data = await get_cockpit_graph(
                target=target,
                run=run,
                job_id=job_id,
                _auth=_auth,
                services=services,
            )
            signature = f"{graph_data['metadata'].get('node_count', 0)}:{graph_data['metadata'].get('edge_count', 0)}"
            if signature != last_signature:
                payload = json.dumps(
                    {
                        "id": f"cockpit-graph-{int(time.time() * 1000)}",
                        "event_type": "graph_snapshot",
                        "job_id": job_id or "",
                        "timestamp": time.time(),
                        "data": graph_data,
                    }
                )
                yield f"event: graph_snapshot\ndata: {payload}\n\n"
                last_signature = signature
            await asyncio.sleep(interval_seconds)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

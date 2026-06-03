"""Cockpit API endpoints for 3D threat graph, events, and manual probes."""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from src.analysis.intelligence.lateral_graph import LateralGraph
from src.dashboard.fastapi.dependencies import (
    check_rate_limit,
    get_queue_client,
    require_auth,
)
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import AttackChainSchema, ErrorResponse
from src.dashboard.fastapi.validation import sanitize_path_segment
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


@router.get(
    "/attack-chains",
    response_model=list[AttackChainSchema],
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get lateral movement attack chains",
)
async def get_attack_chains(
    target: str = Query(..., min_length=1),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> Any:
    """Return identified attack chains linking multiple vulnerabilities and assets."""
    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target)

    # Frontier Logic: Query Kuzu for attack paths
    graph = LateralGraph(db_path=str(target_dir / "graph.db"))
    try:
        raw_chains = graph.find_attack_chains()
    except Exception as e:
        logger.debug("Attack chain query failed (normal if no graph yet): %s", e)
        return []

    formatted: list[dict[str, Any]] = []
    for chain in raw_chains:
        if len(chain) >= 6:
            asset1_id, finding1_id, severity1, asset2_id, finding2_id, severity2 = chain[:6]
        elif len(chain) >= 4:
            asset1_id, finding1_id, asset2_id, finding2_id = chain[:4]
            severity1 = "high"
            severity2 = "critical"
        else:
            continue

        entry: dict[str, Any] = {
            "id": f"chain-{hash(str(chain))}",
            "steps": [
                {
                    "asset_id": str(asset1_id),
                    "finding_id": str(finding1_id),
                    "severity": str(severity1 or "high").lower(),
                },
                {
                    "asset_id": str(asset2_id),
                    "finding_id": str(finding2_id),
                    "severity": str(severity2 or "critical").lower(),
                },
            ],
            "confidence": 0.9 if str(severity2).lower() == "critical" else 0.78,
            "description": f"Potential lateral movement from {asset1_id} to {asset2_id} via {finding1_id}",
        }
        formatted.append(entry)

    # 🛸 Frontier GNN Upgrade: Enrich attack chains with node-embedding predictions
    try:
        from src.intelligence.ml.gnn_predict import GNNPredictor

        graph_data = await get_cockpit_graph(target=target, services=services, _auth=_auth)
        predictor = GNNPredictor()
        predicted_links = predictor.predict_links(
            graph_data["nodes"], graph_data["edges"], threshold=0.65
        )

        for idx, link in enumerate(predicted_links):
            source_id = link["source"]
            target_id = link["target"]
            confidence = link["metadata"]["confidence"]

            chain_entry = {
                "id": f"chain-gnn-{idx}-{hash(source_id + target_id)}",
                "steps": [
                    {
                        "asset_id": source_id,
                        "finding_id": source_id,
                        "severity": "high",
                    },
                    {
                        "asset_id": target_id,
                        "finding_id": target_id,
                        "severity": "critical",
                    },
                ],
                "confidence": confidence,
                "description": f"GNN predicted attack path from {source_id} to {target_id} with {round(confidence * 100, 1)}% confidence",
            }
            formatted.append(chain_entry)
    except Exception as exc:
        logger.debug("Failed to enrich attack chains with GNN predictions: %s", exc)

    return formatted  # type: ignore


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
        source: str, target: str, label: str, metadata: dict[str, Any] | None = None
    ) -> None:
        key = (source, target, label)
        if key not in seen_edges and source in seen_nodes and target in seen_nodes:
            edges.append(
                {"source": source, "target": target, "label": label, "metadata": metadata or {}}
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
    output_root: Path, target_name: str, run: str | None, job_id: str | None
) -> Path | None:
    target_dir = get_safe_target_dir(output_root, target_name)

    if run:
        run_dir = target_dir / run
        if run_dir.exists():
            return run_dir

    if job_id:
        # If job_id is provided, try to find the run directory that matches it
        for child in target_dir.iterdir():
            if child.is_dir():
                summary_path = child / "run_summary.json"
                if summary_path.exists():
                    try:
                        summary = json.loads(summary_path.read_text(encoding="utf-8"))
                        if summary.get("job_id") == job_id:
                            return child
                    except Exception:  # noqa: S112
                        continue

    # Fallback to latest run
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
        # Fallback to any run if summary is missing (e.g. partial run)
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
    run_dir = _get_run_dir_safe(output_root, target, run, job_id)

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

    # 🛸 Frontier ML Upgrade: Predict unseen attack paths using pure-NumPy Graph Neural Networks (GCN)
    predicted_links_count = 0
    optimal_probes = []
    try:
        from src.intelligence.ml.gnn_predict import GNNPredictor, ProbeSelectionRLAgent

        predictor = GNNPredictor()
        predicted_links = predictor.predict_links(graph["nodes"], graph["edges"], threshold=0.65)
        graph["edges"].extend(predicted_links)
        predicted_links_count = len(predicted_links)

        # Instantiate RL agent to recommend optimal probe sequences for the target
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
    "/events",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get cockpit event timeline",
)
async def get_cockpit_events(
    target: str = Query(..., min_length=1),
    run: str | None = Query(None),
    job_id: str | None = Query(None),
    cursor: str | None = Query(None),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Return a timeline of cockpit-relevant events."""
    output_root = services.query.output_root
    get_safe_target_dir(output_root, target)

    # 1. Get findings timeline
    timeline = services.query.get_timeline_data(target)

    # 2. Get analyst notes
    from src.pipeline.analyst_notes import get_all_notes

    notes = get_all_notes(target, output_dir=output_root)

    events = []
    for f in timeline:
        events.append(
            {
                "id": f.get("finding_id"),
                "type": "finding",
                "timestamp": f.get("timestamp"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                "url": f.get("url"),
            }
        )

    for n in notes:
        events.append(
            {
                "id": n.note_id,
                "type": "note",
                "timestamp": n.created_at,
                "author": n.author,
                "note": n.note,
                "finding_id": n.finding_id,
            }
        )

    # Sort by timestamp descending
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Basic cursor-based pagination if needed, for now just return all
    return {"events": events[:100], "next_cursor": None}


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
            graph = await get_cockpit_graph(
                target=target,
                run=run,
                job_id=job_id,
                _auth=_auth,
                services=services,
            )
            signature = (
                f"{graph['metadata'].get('node_count', 0)}:{graph['metadata'].get('edge_count', 0)}"
            )
            if signature != last_signature:
                payload = json.dumps(
                    {
                        "id": f"cockpit-graph-{int(time.time() * 1000)}",
                        "event_type": "graph_snapshot",
                        "job_id": job_id or "",
                        "timestamp": time.time(),
                        "data": graph,
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


@router.get(
    "/forensics",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="List forensic exchanges for a target",
)
async def list_forensic_exchanges(
    target: str = Query(..., min_length=1),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """List forensic exchanges stored for a target."""
    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target)

    exchanges = []
    skipped_count = 0

    # Check root forensics dir
    root_forensics = target_dir / "forensics"
    if root_forensics.exists():
        for f in root_forensics.glob("exchange_*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                exchanges.append(
                    {
                        "exchange_id": data.get("exchange_id"),
                        "timestamp": data.get("timestamp"),
                        "url": data.get("url"),
                        "method": data.get("method"),
                        "response_status": data.get("response", {}).get("status"),
                    }
                )
            except Exception as exc:  # noqa: S112
                logger.warning("Failed to load forensic exchange file %s: %s", f, exc)
                skipped_count += 1
                continue

    # Also check in run directories
    for child in target_dir.iterdir():
        if child.is_dir() and child.name != "forensics" and child.name != "checkpoints":
            run_forensics = child / "forensics"
            if run_forensics.exists():
                for f in run_forensics.glob("exchange_*.json"):
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        exchanges.append(
                            {
                                "exchange_id": data.get("exchange_id"),
                                "timestamp": data.get("timestamp"),
                                "url": data.get("url"),
                                "method": data.get("method"),
                                "response_status": data.get("response", {}).get("status"),
                            }
                        )
                    except Exception as exc:  # noqa: S112
                        logger.warning("Failed to load forensic exchange file %s: %s", f, exc)
                        skipped_count += 1
                        continue

    # Sort by timestamp descending
    exchanges.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return {"exchanges": exchanges[:100], "skipped_count": skipped_count}


@router.get(
    "/forensics/{exchange_id}",
    responses={
        400: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
    },
    summary="Get forensic exchange details",
)
async def get_forensic_exchange(
    exchange_id: str,
    target: str = Query(..., min_length=1),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Retrieve a forensic exchange artifact from disk."""
    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target)

    # SEC-FIX: Sanitize exchange_id
    safe_id = sanitize_path_segment(exchange_id)
    forensics_dir = target_dir / "forensics"
    file_path = forensics_dir / f"exchange_{safe_id}.json"

    if not file_path.exists():
        # Also check in run directories if not found in root forensics
        found = False
        for child in target_dir.iterdir():
            if child.is_dir():
                candidate = child / "forensics" / f"exchange_{safe_id}.json"
                if candidate.exists():
                    file_path = candidate
                    found = True
                    break
        if not found:
            raise HTTPException(status_code=404, detail="Forensic exchange not found")

    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return cast(dict[str, Any], data)
    except Exception as e:
        logger.error("Failed to read forensic exchange %s: %s", exchange_id, e)
        raise HTTPException(status_code=500, detail="Failed to load forensic data")


@router.post(
    "/probes",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Trigger a manual forensic probe",
)
async def trigger_cockpit_probe(
    target: str = Query(..., min_length=1),
    url: str = Query(..., min_length=1),
    method: str = "GET",
    _auth: Any = Depends(require_auth),
    _rate_limit: Any = Depends(check_rate_limit),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Trigger a manual probe with scope validation and forensic capture."""
    from src.analysis.passive.runtime import fetch_response
    from src.core.utils.url_validation import is_safe_url

    output_root = services.query.output_root
    get_safe_target_dir(output_root, target)

    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="URL is out of scope or unsafe")

    try:
        result = fetch_response(
            url,
            timeout_seconds=15,
            max_bytes=1024 * 512,  # 512KB cap
            method=method.upper(),
            capture_forensics=True,
            output_dir=output_root,
            target_name=target,
        )
    except Exception as e:
        logger.error("Manual probe failed: %s", e)
        raise HTTPException(status_code=502, detail=f"Probe failed: {str(e)}")

    if not result:
        raise HTTPException(status_code=502, detail="Probe did not return a response")

    return cast(
        dict[str, Any],
        {
            "status": "success",
            "exchange_id": str(result.get("exchange_id", "")),
            "status_code": int(result.get("status_code", 0)),
            "url": str(result.get("url", "")),
        },
    )


# ---------------------------------------------------------
# Interactive 3D Exploit Sandbox & Time-Travel Replay
# ---------------------------------------------------------

from pydantic import BaseModel


class SandboxLaunchRequest(BaseModel):
    target_node: str
    image: str = "ubuntu:latest"


class TerminalCommandRequest(BaseModel):
    command: str


@router.post(
    "/sandbox/launch",
    summary="Launch a safe dockerized sandbox for a node",
)
async def launch_sandbox(
    request: SandboxLaunchRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    from src.dashboard.fastapi.sandbox_service import sandbox_manager

    sandbox_id = sandbox_manager.launch_sandbox(request.target_node, request.image)
    return {"status": "success", "sandbox_id": sandbox_id}


@router.get(
    "/sandbox/{sandbox_id}/state",
    summary="View chronological state of the sandbox for Time-Travel Replay",
)
async def get_sandbox_state(
    sandbox_id: str,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    from src.dashboard.fastapi.sandbox_service import sandbox_manager

    history = sandbox_manager.get_chronological_state(sandbox_id)
    return {"status": "success", "history": history}


@router.post(
    "/sandbox/{sandbox_id}/terminal",
    summary="Execute manual command in the sandbox terminal",
)
async def execute_terminal(
    sandbox_id: str,
    request: TerminalCommandRequest,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    from src.dashboard.fastapi.sandbox_service import sandbox_manager

    try:
        output = sandbox_manager.execute_terminal_command(sandbox_id, request.command)
        return {"status": "success", "output": output}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

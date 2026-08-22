"""Cockpit API endpoints for 3D threat graph data (nodes/edges)."""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.cockpit.edges import (
    _build_run_artifact_graph,
    _merge_graphs,
)
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import ErrorResponse
from src.intelligence.graph.threat_graph import load_lateral_movement_graph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cockpit", tags=["Cockpit"])


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
    optimal_probes: list[Any] = []

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

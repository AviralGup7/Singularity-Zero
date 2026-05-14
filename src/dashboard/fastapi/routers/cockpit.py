"""Cockpit API endpoints for 3D threat graph, events, and manual probes."""

import json
import logging
from pathlib import Path
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.dashboard.fastapi.dependencies import check_rate_limit, get_queue_client, require_auth, get_config
from src.dashboard.fastapi.schemas import ErrorResponse, AttackChainSchema
from src.dashboard.fastapi.validation import validate_target_name
from src.analysis.intelligence.lateral_graph import LateralGraph

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cockpit", tags=["Cockpit"])

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
    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name")

    # Frontier Logic: Query Kuzu for attack paths
    # In a real mesh, the DB path might be shared or per-target
    graph = LateralGraph(db_path=f"output/{target}/graph.db")
    try:
        raw_chains = graph.find_attack_chains()
    except Exception as e:
        logger.debug("Attack chain query failed (normal if no graph yet): %s", e)
        return []
    
    formatted: list[dict[str, Any]] = []
    for chain in raw_chains:
        # Map [a1.id, f1.id, a2.id, f2.id] -> AttackChainSchema
        entry: dict[str, Any] = {
            "id": f"chain-{hash(str(chain))}",
            "steps": [
                {"asset_id": str(chain[0]), "finding_id": str(chain[1]), "severity": "high"},
                {"asset_id": str(chain[2]), "finding_id": str(chain[3]), "severity": "critical"}
            ],
            "confidence": 0.9,
            "description": f"Potential lateral movement from {chain[0]} to {chain[2]} via {chain[1]}"
        }
        formatted.append(entry)
        
    return formatted # type: ignore


def _get_run_dir(output_root: Path, target: str, run: str | None, job_id: str | None) -> Path | None:
    target_dir = output_root / target
    if not target_dir.exists():
        return None

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
                    except Exception:
                        continue

    # Fallback to latest run
    runs = [
        child
        for child in target_dir.iterdir()
        if child.is_dir() and (child / "run_summary.json").exists()
    ]
    if not runs:
        # Fallback to any run if summary is missing (e.g. partial run)
        runs = [child for child in target_dir.iterdir() if child.is_dir() and child.name != "checkpoints"]

    if not runs:
        return None

    return max(runs, key=lambda d: d.name)


@router.get(
    "/graph",
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get 3D threat graph data",
)
async def get_cockpit_graph(
    target: str = Query(..., min_length=1),
    run: str | None = Query(None),
    job_id: str | None = Query(None),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Build and return 3D threat graph data for the cockpit."""
    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    run_dir = _get_run_dir(output_root, target, run, job_id)

    if not run_dir:
        return {"nodes": [], "edges": [], "metadata": {"target": target}}

    nodes = []
    edges = []
    seen_nodes = set()

    # 1. Add Endpoint Nodes from urls.txt
    urls_path = run_dir / "urls.txt"
    if urls_path.exists():
        try:
            urls = urls_path.read_text(encoding="utf-8").splitlines()
            for url in urls[:200]:  # Limit for MVP performance
                url = url.strip()
                if not url: continue
                node_id = f"url:{url}"
                if node_id not in seen_nodes:
                    nodes.append({
                        "id": node_id,
                        "type": "endpoint",
                        "label": url.split("://")[-1],
                        "severity": "info",
                        "metadata": {"url": url}
                    })
                    seen_nodes.add(node_id)
        except Exception as e:
            logger.warning("Failed to read urls.txt for cockpit: %s", e)

    # 2. Add Finding Nodes from findings.json
    findings_path = run_dir / "findings.json"
    if findings_path.exists():
        try:
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            for finding in findings:
                finding_id = finding.get("id") or finding.get("finding_id") or f"f-{id(finding)}"
                node_id = f"finding:{finding_id}"
                if node_id not in seen_nodes:
                    nodes.append({
                        "id": node_id,
                        "type": "finding",
                        "label": finding.get("title", "Untitled Finding"),
                        "severity": finding.get("severity", "info").lower(),
                        "metadata": finding
                    })
                    seen_nodes.add(node_id)

                # Link finding to its URL
                target_url = finding.get("url")
                if target_url:
                    url_node_id = f"url:{target_url}"
                    if url_node_id in seen_nodes:
                        edges.append({
                            "source": url_node_id,
                            "target": node_id,
                            "label": "affects"
                        })
        except Exception as e:
            logger.warning("Failed to read findings.json for cockpit: %s", e)

    return {
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "target": target,
            "run": run_dir.name,
            "job_id": job_id
        }
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
    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name")

    # 1. Get findings timeline
    timeline = services.query.get_timeline_data(target)

    # 2. Get analyst notes
    from src.pipeline.analyst_notes import get_all_notes
    notes = get_all_notes(target, output_dir=services.query.output_root)

    events = []
    for f in timeline:
        events.append({
            "id": f.get("finding_id"),
            "type": "finding",
            "timestamp": f.get("timestamp"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "url": f.get("url")
        })

    for n in notes:
        events.append({
            "id": n.note_id,
            "type": "note",
            "timestamp": n.created_at,
            "author": n.author,
            "note": n.note,
            "finding_id": n.finding_id
        })

    # Sort by timestamp descending
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    # Basic cursor-based pagination if needed, for now just return all
    return {
        "events": events[:100],
        "next_cursor": None
    }


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
    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    target_dir = output_root / target
    if not target_dir.exists():
        return {"exchanges": []}

    exchanges = []

    # Check root forensics dir
    root_forensics = target_dir / "forensics"
    if root_forensics.exists():
        for f in root_forensics.glob("exchange_*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                exchanges.append({
                    "exchange_id": data.get("exchange_id"),
                    "timestamp": data.get("timestamp"),
                    "url": data.get("url"),
                    "method": data.get("method"),
                    "response_status": data.get("response", {}).get("status")
                })
            except Exception:
                continue

    # Also check in run directories
    for child in target_dir.iterdir():
        if child.is_dir() and child.name != "forensics" and child.name != "checkpoints":
            run_forensics = child / "forensics"
            if run_forensics.exists():
                for f in run_forensics.glob("exchange_*.json"):
                    try:
                        data = json.loads(f.read_text(encoding="utf-8"))
                        exchanges.append({
                            "exchange_id": data.get("exchange_id"),
                            "timestamp": data.get("timestamp"),
                            "url": data.get("url"),
                            "method": data.get("method"),
                            "response_status": data.get("response", {}).get("status")
                        })
                    except Exception:
                        continue

    # Sort by timestamp descending
    exchanges.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    return {"exchanges": exchanges[:100]}


@router.get(
    "/forensics/{exchange_id}",
    responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get forensic exchange details",
)
async def get_forensic_exchange(
    exchange_id: str,
    target: str = Query(..., min_length=1),
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Retrieve a forensic exchange artifact from disk."""
    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name")

    output_root = services.query.output_root
    forensics_dir = output_root / target / "forensics"
    file_path = forensics_dir / f"exchange_{exchange_id}.json"

    if not file_path.exists():
        # Also check in run directories if not found in root forensics
        target_dir = output_root / target
        found = False
        if target_dir.exists():
            for child in target_dir.iterdir():
                if child.is_dir():
                    candidate = child / "forensics" / f"exchange_{exchange_id}.json"
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

    if not validate_target_name(target):
        raise HTTPException(status_code=400, detail="Invalid target name")

    if not is_safe_url(url):
        raise HTTPException(status_code=400, detail="URL is out of scope or unsafe")

    output_root = services.query.output_root
    # We use the target directory as the output_dir for forensics

    try:
        result = fetch_response(
            url,
            timeout_seconds=15,
            max_bytes=1024 * 512,  # 512KB cap
            method=method.upper(),
            capture_forensics=True,
            output_dir=output_root,
            target_name=target
        )
    except Exception as e:
        logger.error("Manual probe failed: %s", e)
        raise HTTPException(status_code=502, detail=f"Probe failed: {str(e)}")

    if not result:
        raise HTTPException(status_code=502, detail="Probe did not return a response")

    return cast(dict[str, Any], {
        "status": "success",
        "exchange_id": str(result.get("exchange_id", "")),
        "status_code": int(result.get("status_code", 0)),
        "url": str(result.get("url", ""))
    })

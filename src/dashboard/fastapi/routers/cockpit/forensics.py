"""Cockpit API endpoints for forensic exchange artifacts."""

import json
import logging
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import ErrorResponse
from src.dashboard.fastapi.validation import sanitize_path_segment

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/cockpit", tags=["Cockpit"])


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
            except Exception as exc:
                logger.warning("Failed to load forensic exchange file %s: %s", f, exc)
                skipped_count += 1

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
                    except Exception as exc:
                        logger.warning("Failed to load forensic exchange file %s: %s", f, exc)
                        skipped_count += 1

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

    safe_id = sanitize_path_segment(exchange_id)
    forensics_dir = target_dir / "forensics"
    file_path = forensics_dir / f"exchange_{safe_id}.json"

    if not file_path.exists():
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

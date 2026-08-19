"""Cockpit API endpoints for lateral movement attack chains."""

import hashlib
import logging
from typing import Any

from fastapi import APIRouter, Depends, Query

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.utils import get_safe_target_dir
from src.dashboard.fastapi.schemas import AttackChainSchema, ErrorResponse

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
) -> list[AttackChainSchema]:
    """Return identified attack chains linking multiple vulnerabilities and assets."""
    output_root = services.query.output_root
    target_dir = get_safe_target_dir(output_root, target)

    from src.core.contracts.protocol_registry import get_lateral_graph_cls

    LateralGraphCls = get_lateral_graph_cls()
    if LateralGraphCls is None:
        logger.debug("LateralGraph not available")
        return []
    graph = LateralGraphCls(db_path=str(target_dir / "graph.db"))
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
            "id": f"chain-{hashlib.sha256(str(chain).encode()).hexdigest()[:16]}",
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

    return formatted  # type: ignore

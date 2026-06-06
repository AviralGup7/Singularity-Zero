"""Cockpit API endpoints for lateral movement attack chains."""

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

    from src.analysis.intelligence.lateral_graph import LateralGraph

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

    try:
        from src.dashboard.fastapi.routers.cockpit.nodes import get_cockpit_graph

        graph_data = await get_cockpit_graph(target=target, services=services, _auth=_auth)
        from src.intelligence.ml.gnn_predict import GNNPredictor

        predictor = GNNPredictor()
        predicted_links = predictor.predict_links(
            graph_data["nodes"], graph_data["edges"], threshold=0.65
        )

        for idx, link in enumerate(predicted_links):
            source_id = link["source"]
            tgt_id = link["target"]
            confidence = link["metadata"]["confidence"]

            chain_entry: dict[str, Any] = {
                "id": f"chain-gnn-{idx}-{hash(source_id + tgt_id)}",
                "steps": [
                    {
                        "asset_id": source_id,
                        "finding_id": source_id,
                        "severity": "high",
                    },
                    {
                        "asset_id": tgt_id,
                        "finding_id": tgt_id,
                        "severity": "critical",
                    },
                ],
                "confidence": confidence,
                "description": f"GNN predicted attack path from {source_id} to {tgt_id} with {round(confidence * 100, 1)}% confidence",
            }
            formatted.append(chain_entry)
    except Exception as exc:
        logger.debug("Failed to enrich attack chains with GNN predictions: %s", exc)

    return formatted  # type: ignore

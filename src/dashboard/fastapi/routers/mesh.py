"""Mesh operations endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from src.dashboard.fastapi.dependencies import require_admin

router = APIRouter(prefix="/api/mesh", tags=["Mesh"])


@router.post(
    "/elect-leader",
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
    summary="Manually trigger deterministic local leader election (admin only)",
)
async def elect_leader(
    request: Request,
    _admin: Any = Depends(require_admin),
) -> dict[str, Any]:
    """Manually trigger deterministic local leader election.

    SECURITY: requires admin authentication. The previous unauthenticated
    version allowed any caller to disrupt the mesh by forcing a leader
    election under a forged identity.
    """
    gossip = getattr(request.app.state, "gossip", None)
    if not gossip:
        raise HTTPException(status_code=503, detail="Mesh gossip engine is not active")
    leader_id = gossip.elect_leader()
    return {"leader_id": leader_id, "mesh": gossip.mesh_health()}

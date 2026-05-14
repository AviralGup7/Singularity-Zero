"""Mesh operations endpoints."""

from typing import Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/mesh", tags=["Mesh"])


@router.post("/elect-leader")
async def elect_leader(request: Request) -> dict[str, Any]:
    """Manually trigger deterministic local leader election."""
    gossip = getattr(request.app.state, "gossip", None)
    if not gossip:
        raise HTTPException(status_code=503, detail="Mesh gossip engine is not active")
    leader_id = gossip.elect_leader()
    return {"leader_id": leader_id, "mesh": gossip.mesh_health()}

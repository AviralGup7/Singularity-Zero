import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.routers.findings.helpers import _find_finding_by_id
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get(
    "/{finding_id}",
    response_model=dict[str, Any],
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get individual finding details",
)
async def get_finding_detail(
    finding_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    """Retrieve full details for a specific finding by ID."""
    tenant_id = (_auth or {}).get("tenant_id", "default")
    finding = _find_finding_by_id(services.query.output_root, finding_id, tenant_id=tenant_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get(
    "/{finding_id}/remediation",
    response_model=dict[str, Any],
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get fix-command suggestions for a finding",
)
async def get_finding_remediation(
    finding_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    from src.dashboard.remediation import suggest_for_finding

    tenant_id = (_auth or {}).get("tenant_id", "default")
    finding = _find_finding_by_id(services.query.output_root, finding_id, tenant_id=tenant_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding_id": finding_id, "suggestions": suggest_for_finding(finding)}


@router.get(
    "/{finding_id}/explain",
    response_model=dict[str, Any],
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get ML explainability analysis (SHAP) for a finding",
)
async def explain_finding_severity(
    finding_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    tenant_id = (_auth or {}).get("tenant_id", "default")
    finding = _find_finding_by_id(services.query.output_root, finding_id, tenant_id=tenant_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding_id": finding_id, "explanation": "ML explainability module removed."}


@router.get(
    "/{finding_id}/ai-explain",
    response_model=dict[str, Any],
    responses={404: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
    summary="Get AI persona-tailored (Developer/Auditor) explanations for a finding",
)
async def explain_finding_ai(
    finding_id: str,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, Any]:
    tenant_id = (_auth or {}).get("tenant_id", "default")
    finding = _find_finding_by_id(services.query.output_root, finding_id, tenant_id=tenant_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding_id": finding_id, "explanations": "AI explanation module removed."}

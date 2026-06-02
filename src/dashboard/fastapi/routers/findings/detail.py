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
    from src.intelligence.ml.shap_explainer import SHAPExplainer

    tenant_id = (_auth or {}).get("tenant_id", "default")
    finding = _find_finding_by_id(services.query.output_root, finding_id, tenant_id=tenant_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    try:
        explainer = SHAPExplainer()
        explanation = explainer.explain(finding)
        return explanation
    except Exception as exc:
        logger.exception("Failed to generate explainability analysis: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Failed to generate explainability analysis: {exc}"
        )


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

    try:
        from src.intelligence.ml.llm_service import LLMService

        service = LLMService.get_instance()
        explanation = await service.explain_finding(finding)
        return {"finding_id": finding_id, "explanations": explanation}
    except Exception as exc:
        logger.exception("Failed to generate AI explainability analysis: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to generate AI explanations: {exc}")

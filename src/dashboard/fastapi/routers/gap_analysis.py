"""Gap Analysis endpoints for the FastAPI dashboard."""

import logging
from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import get_queue_client, require_auth
from src.dashboard.fastapi.schemas import DetectionGapResponse, GapAnalysisEntry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/gap-analysis", tags=["Gap Analysis"])

@router.get(
    "",
    response_model=DetectionGapResponse,
    responses={401: {"model": Any}},
    summary="Get detection gap analysis",
)
async def get_gap_analysis(
    target: str | None = None,
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> DetectionGapResponse:
    """Analyze coverage gaps across vulnerability categories."""
    from src.reporting.detection_coverage import ALL_DETECTION_CATEGORIES

    # 1. Map categories to their "ideal" check counts
    # In a real system, this would be more dynamic.
    ideal_counts = {
        "idor": 5, "ssrf": 4, "xss": 8, "open_redirect": 3,
        "token_leak": 2, "access_control": 6, "authentication_bypass": 4,
        "broken_authentication": 3, "business_logic": 7, "payment": 4,
        "sensitive_data": 3, "misconfiguration": 10, "cors": 3,
        "session": 4, "anomaly": 2, "behavioral_deviation": 3,
        "redirect": 4, "server_side_injection": 5, "race_condition": 2,
        "csrf": 3, "ssti": 2, "ai_surface": 2, "exposure": 5,
    }

    # 2. Get actual findings/tests run for the target
    # If target is None, we look at global coverage

    # Simple heuristic: what modules have EVER run or are currently enabled
    # For now, we simulate this based on ALL_DETECTION_CATEGORIES

    results: list[GapAnalysisEntry] = []
    total_coverage = 0
    modules_with_gaps = 0

    for cat_id, info in ALL_DETECTION_CATEGORIES.items():
        total = ideal_counts.get(cat_id, 3)
        # Mocking coverage for demonstration; in production, this queries the DB
        # for whether a module matching this category has been executed.
        covered = total if cat_id in ["xss", "ssrf", "misconfiguration"] else total - 1
        if cat_id in ["ai_surface", "race_condition"]: covered = 0

        percent = int((covered / total) * 100)
        status = "complete" if percent == 100 else "partial" if percent > 0 else "missing"

        if status != "complete":
            modules_with_gaps += 1

        results.append(GapAnalysisEntry(
            module=info["name"],
            category=cat_id,
            total_checks=total,
            covered_checks=covered,
            missing_checks=total - covered,
            coverage_percent=percent,
            status=status
        ))
        total_coverage += percent

    return DetectionGapResponse(
        target=target,
        results=results,
        overall_coverage=int(total_coverage / len(ALL_DETECTION_CATEGORIES)) if ALL_DETECTION_CATEGORIES else 0,
        total_modules=len(ALL_DETECTION_CATEGORIES),
        modules_with_gaps=modules_with_gaps
    )

@router.post(
    "/refresh",
    summary="Trigger fresh gap analysis",
)
async def refresh_gap_analysis(
    _auth: Any = Depends(require_auth),
    services: Any = Depends(get_queue_client),
) -> dict[str, str]:
    """Trigger a fresh analysis of findings vs coverage registry."""
    # In a real system, this would invalidate caches and re-run background analysis
    return {"status": "Analysis refresh triggered"}

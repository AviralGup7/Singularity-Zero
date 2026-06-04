"""Learning subsystem endpoints for the FastAPI dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.dashboard.fastapi.dependencies import get_learning_integration, require_auth
from src.dashboard.fastapi.schemas import (
    FeedbackEventEntry,
    FpPatternEntry,
    TelemetryKpis,
    ThresholdHistoryEntry,
)
from src.learning.integration import LearningIntegration

router = APIRouter(prefix="/api/learning", tags=["learning"])


@router.get(
    "/thresholds",
    response_model=list[ThresholdHistoryEntry],
    responses={401: {"description": "Unauthorized"}},
    summary="Get threshold history (authenticated)",
)
async def get_threshold_history(
    run_id: str | None = None,
    category: str | None = None,
    limit: int = 50,
    learning: LearningIntegration = Depends(get_learning_integration),
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Get the history of automated threshold calibrations (Phase 5.3)."""
    return learning.store.get_threshold_history(run_id=run_id, category=category)[:limit]


@router.get(
    "/fp-patterns",
    response_model=list[FpPatternEntry],
    responses={401: {"description": "Unauthorized"}},
    summary="Get learned FP patterns (authenticated)",
)
async def get_fp_patterns(
    category: str | None = None,
    active_only: bool = True,
    learning: LearningIntegration = Depends(get_learning_integration),
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Get the current repository of learned false positive patterns (Phase 5.3)."""
    return learning.store.get_fp_patterns(category=category, active_only=active_only)


@router.get(
    "/kpis",
    response_model=TelemetryKpis,
    responses={401: {"description": "Unauthorized"}},
    summary="Get learning KPIs (authenticated)",
)
async def get_learning_kpis(
    target: str | None = None,
    learning: LearningIntegration = Depends(get_learning_integration),
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Get high-level learning performance indicators (Phase 5.3)."""
    try:
        kpis = learning.get_kpis(target=target)
        return kpis.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to compute KPIs: {exc}")


@router.get(
    "/feedback",
    response_model=list[FeedbackEventEntry],
    responses={401: {"description": "Unauthorized"}},
    summary="Get feedback events (authenticated)",
)
async def get_feedback_events(
    limit: int = Query(100, ge=1, le=10000),
    run_id: str | None = None,
    learning: LearningIntegration = Depends(get_learning_integration),
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Get feedback events for analysis and inspection (Phase 5.3)."""
    try:
        if run_id:
            return learning.store.get_feedback_events_for_run(run_id)
        return learning.store.get_feedback_events(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve feedback events: {exc}")


@router.get(
    "/db-stats",
    response_model=dict[str, int],
    responses={401: {"description": "Unauthorized"}},
    summary="Get telemetry database statistics (authenticated)",
)
async def get_learning_db_stats(
    learning: LearningIntegration = Depends(get_learning_integration),
    _auth: Any = Depends(require_auth),
) -> dict[str, int]:
    """Get statistics about the telemetry database (Phase 5.3)."""
    return learning.get_db_size()

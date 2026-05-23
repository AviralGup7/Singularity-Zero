"""Learning subsystem endpoints for the FastAPI dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from src.dashboard.fastapi.dependencies import get_learning_integration
from src.dashboard.fastapi.schemas import (
    FeedbackEventEntry,
    FpPatternEntry,
    TelemetryKpis,
    ThresholdHistoryEntry,
)
from src.learning.integration import LearningIntegration

router = APIRouter(prefix="/api/learning", tags=["learning"])


@router.get("/thresholds", response_model=list[ThresholdHistoryEntry])
async def get_threshold_history(
    run_id: str | None = None,
    category: str | None = None,
    limit: int = 50,
    learning: LearningIntegration = Depends(get_learning_integration),
) -> list[dict[str, Any]]:
    """Get the history of automated threshold calibrations (Phase 5.3)."""
    return learning.store.get_threshold_history(run_id=run_id, category=category)[:limit]


@router.get("/fp-patterns", response_model=list[FpPatternEntry])
async def get_fp_patterns(
    category: str | None = None,
    active_only: bool = True,
    learning: LearningIntegration = Depends(get_learning_integration),
) -> list[dict[str, Any]]:
    """Get the current repository of learned false positive patterns (Phase 5.3)."""
    return learning.store.get_fp_patterns(category=category, active_only=active_only)


@router.get("/kpis", response_model=TelemetryKpis)
async def get_learning_kpis(
    target: str | None = None,
    learning: LearningIntegration = Depends(get_learning_integration),
) -> dict[str, Any]:
    """Get high-level learning performance indicators (Phase 5.3)."""
    try:
        kpis = learning.get_kpis(target=target)
        return kpis.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to compute KPIs: {exc}")


@router.get("/feedback", response_model=list[FeedbackEventEntry])
async def get_feedback_events(
    limit: int = Query(100, ge=1, le=10000),
    run_id: str | None = None,
    learning: LearningIntegration = Depends(get_learning_integration),
) -> list[dict[str, Any]]:
    """Get feedback events for analysis and inspection (Phase 5.3)."""
    try:
        if run_id:
            return learning.store.get_feedback_events_for_run(run_id)
        return learning.store.get_feedback_events(limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve feedback events: {exc}")


@router.get("/db-stats", response_model=dict[str, int])
async def get_learning_db_stats(
    learning: LearningIntegration = Depends(get_learning_integration),
) -> dict[str, int]:
    """Get statistics about the telemetry database (Phase 5.3)."""
    return learning.get_db_size()

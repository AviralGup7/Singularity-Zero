"""Findings router package - re-exports combined router."""

from __future__ import annotations

import logging
from typing import Any

from .bulk import router as bulk_router
from .crud import router as crud_router
from .delete import router as delete_router
from .detail import router as detail_router
from .summary import router as summary_router
from .timeline import router as timeline_router

try:
    from .helpers import (
        _collect_timeline_events,
        _find_finding_by_id,
        _seeded_timeline_events,
        _telemetry_timeline_events,
    )
except Exception:  # pragma: no cover - defensive
    _collect_timeline_events = None  # type: ignore[assignment]
    _seeded_timeline_events = None  # type: ignore[assignment]
    _telemetry_timeline_events = None  # type: ignore[assignment]
    _find_finding_by_id = None  # type: ignore[assignment]

try:
    from .crud import update_finding
except Exception:  # pragma: no cover - defensive
    update_finding = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

router: Any = None

try:
    from fastapi import APIRouter

    _router = APIRouter()
    _router.include_router(crud_router)
    _router.include_router(bulk_router)
    _router.include_router(delete_router)
    _router.include_router(detail_router)
    _router.include_router(summary_router)
    _router.include_router(timeline_router)
    router = _router
except Exception:
    logger.exception("Failed to initialize findings router — failing fast so the issue is visible")
    raise

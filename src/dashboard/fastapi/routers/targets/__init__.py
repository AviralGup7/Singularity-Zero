"""Aggregation router for the targets sub-package.

This package deconstructs the monolithic targets.py router into single-concern
files while re-exporting public APIs and the combined router.
"""

from fastapi import APIRouter

from .crud import router as crud_router
from .crud import list_all_findings
from .scoring import router as scoring_router
from src.dashboard.fastapi.schemas import (
    TargetComparisonDetail,
    TargetComparisonResponse,
)
from .validation import (
    TargetFindingsResponse,
    _normalize_finding_payload,
    _validate_target_name,
    is_target_owned_by_tenant,
    verify_tenant_boundary,
)

router = APIRouter()

router.include_router(crud_router)
router.include_router(scoring_router)

__all__ = [
    "router",
    "is_target_owned_by_tenant",
    "verify_tenant_boundary",
    "_normalize_finding_payload",
    "_validate_target_name",
    "TargetComparisonResponse",
    "TargetComparisonDetail",
    "TargetFindingsResponse",
    "list_all_findings",
]

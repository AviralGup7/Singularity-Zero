"""Re-export shim for the targets router module.

The monolithic targets.py has been deconstructed into the targets/ package
(crud.py, scoring.py, validation.py). This shim preserves backward
compatibility by re-exporting the combined router and all public symbols
so that existing imports continue to work.
"""

from fastapi import APIRouter

from src.dashboard.fastapi.routers.targets.crud import list_all_findings
from src.dashboard.fastapi.routers.targets.crud import router as crud_router
from src.dashboard.fastapi.routers.targets.scoring import router as scoring_router
from src.dashboard.fastapi.routers.targets.validation import (
    TargetFindingsResponse,
    _normalize_finding_payload,
    _validate_target_name,
    is_target_owned_by_tenant,
    verify_tenant_boundary,
)
from src.dashboard.fastapi.schemas import (
    TargetComparisonDetail,
    TargetComparisonResponse,
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

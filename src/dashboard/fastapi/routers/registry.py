"""Registry and configuration endpoints for the FastAPI dashboard."""

import logging
from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import require_auth
from src.dashboard.fastapi.schemas import (
    ErrorResponse,
    RegistryAnalysisOptions,
    RegistryModePresets,
    RegistryModuleOptions,
    RegistryResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/registry", tags=["Registry"])


@router.get(
    "/modules",
    response_model=RegistryModuleOptions,
    responses={401: {"model": ErrorResponse}},
    summary="Get module options",
)
async def get_module_options(
    _auth: Any = Depends(require_auth),
) -> RegistryModuleOptions:
    """Return available module options and groups."""
    from src.dashboard.registry import MODULE_GROUPS, MODULE_OPTIONS

    return RegistryModuleOptions(options=MODULE_OPTIONS, groups=MODULE_GROUPS)


@router.get(
    "/analysis",
    response_model=RegistryAnalysisOptions,
    responses={401: {"model": ErrorResponse}},
    summary="Get analysis check options",
)
async def get_analysis_options(
    _auth: Any = Depends(require_auth),
) -> RegistryAnalysisOptions:
    """Return analysis check options, control groups, and focus presets."""
    from src.dashboard.registry import (
        ANALYSIS_CHECK_OPTIONS,
        ANALYSIS_CONTROL_GROUPS,
        ANALYSIS_FOCUS_PRESETS,
    )

    return RegistryAnalysisOptions(
        check_options=ANALYSIS_CHECK_OPTIONS,
        control_groups=ANALYSIS_CONTROL_GROUPS,
        focus_presets=ANALYSIS_FOCUS_PRESETS,
    )


@router.get(
    "/modes",
    response_model=RegistryModePresets,
    responses={401: {"model": ErrorResponse}},
    summary="Get mode presets",
)
async def get_mode_presets(
    _auth: Any = Depends(require_auth),
) -> RegistryModePresets:
    """Return mode presets and stage labels."""
    from src.dashboard.registry import MODE_PRESETS, STAGE_LABELS

    return RegistryModePresets(presets=MODE_PRESETS, stage_labels=STAGE_LABELS)


@router.get(
    "",
    response_model=RegistryResponse,
    responses={401: {"model": ErrorResponse}},
    summary="Get combined registry data",
)
async def get_registry(
    _auth: Any = Depends(require_auth),
) -> RegistryResponse:
    """Return all registry data (modules, analysis, modes) in a single response."""
    from src.dashboard.registry import (
        ANALYSIS_CHECK_OPTIONS,
        ANALYSIS_CONTROL_GROUPS,
        ANALYSIS_FOCUS_PRESETS,
        MODE_PRESETS,
        MODULE_GROUPS,
        MODULE_OPTIONS,
        STAGE_LABELS,
    )

    return RegistryResponse(
        modules=RegistryModuleOptions(options=MODULE_OPTIONS, groups=MODULE_GROUPS),
        analysis=RegistryAnalysisOptions(
            check_options=ANALYSIS_CHECK_OPTIONS,
            control_groups=ANALYSIS_CONTROL_GROUPS,
            focus_presets=ANALYSIS_FOCUS_PRESETS,
        ),
        modes=RegistryModePresets(presets=MODE_PRESETS, stage_labels=STAGE_LABELS),
    )

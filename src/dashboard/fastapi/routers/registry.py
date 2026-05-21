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
    from src.analysis.plugins import analysis_check_options
    from src.core.plugins.loader import dynamic_plugin_payload
    from src.dashboard.registry import (
        ANALYSIS_CONTROL_GROUPS,
        ANALYSIS_FOCUS_PRESETS,
    )

    plugin_payload = dynamic_plugin_payload()
    return RegistryAnalysisOptions(
        check_options=analysis_check_options(),
        control_groups=ANALYSIS_CONTROL_GROUPS,
        focus_presets=ANALYSIS_FOCUS_PRESETS,
        dynamic_plugins=plugin_payload["plugins"],
        invalid_dynamic_plugins=plugin_payload["invalid"],
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
    from src.analysis.plugins import analysis_check_options
    from src.core.capabilities import generate_capability_manifest
    from src.core.plugins.loader import dynamic_plugin_payload
    from src.dashboard.registry import (
        ANALYSIS_CONTROL_GROUPS,
        ANALYSIS_FOCUS_PRESETS,
        MODE_PRESETS,
        MODULE_GROUPS,
        MODULE_OPTIONS,
        STAGE_LABELS,
    )

    plugin_payload = dynamic_plugin_payload()
    return RegistryResponse(
        modules=RegistryModuleOptions(options=MODULE_OPTIONS, groups=MODULE_GROUPS),
        analysis=RegistryAnalysisOptions(
            check_options=analysis_check_options(),
            control_groups=ANALYSIS_CONTROL_GROUPS,
            focus_presets=ANALYSIS_FOCUS_PRESETS,
            dynamic_plugins=plugin_payload["plugins"],
            invalid_dynamic_plugins=plugin_payload["invalid"],
        ),
        modes=RegistryModePresets(presets=MODE_PRESETS, stage_labels=STAGE_LABELS),
        capabilities=generate_capability_manifest().to_dict(),
    )


@router.get(
    "/plugins",
    responses={401: {"model": ErrorResponse}},
    summary="Get dynamic plugin catalog",
)
async def get_dynamic_plugins(
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return hot-loaded third-party plugin manifests and validation errors."""
    from src.core.plugins.loader import dynamic_plugin_payload

    return dynamic_plugin_payload()


@router.get(
    "/capabilities",
    responses={401: {"model": ErrorResponse}},
    summary="Get generated capability manifest",
)
async def get_capabilities(
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return the generated capability manifest for built-in and dynamic plugins."""
    from src.core.capabilities import generate_capability_manifest

    return generate_capability_manifest().to_dict()

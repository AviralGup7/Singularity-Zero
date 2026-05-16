"""Router aggregation for the FastAPI dashboard."""

from typing import cast
from fastapi import APIRouter

from .bloom import router as bloom_router
from .cache import router as cache_router
from .cockpit import router as cockpit_router
from .export import router as export_router
from .findings import router as findings_router
from .gap_analysis import router as gap_analysis_router
from .health import router as health_router
from .jobs import router as jobs_router
from .mesh import router as mesh_router
from .notes import router as notes_router
from .registry import router as registry_router
from .replay import router as replay_router
from .risk import router as risk_router
from .security import router as security_router
from .targets import router as targets_router
from .tracing import router as tracing_router

try:
    from .imports import router as imports_router
except RuntimeError as exc:
    if "python-multipart" not in str(exc):
        raise
    imports_router = cast(APIRouter, None)

api_router = APIRouter()

api_router.include_router(health_router, tags=["Health"])
api_router.include_router(bloom_router, tags=["Bloom"])
api_router.include_router(cockpit_router, tags=["Cockpit"])
api_router.include_router(jobs_router, tags=["Jobs"])
api_router.include_router(mesh_router, tags=["Mesh"])
api_router.include_router(targets_router, tags=["Targets"])
api_router.include_router(findings_router, tags=["Findings"])
api_router.include_router(cache_router, tags=["Cache"])
api_router.include_router(notes_router, tags=["Notes"])
api_router.include_router(export_router, tags=["Export"])
api_router.include_router(replay_router, tags=["Replay"])
api_router.include_router(risk_router, tags=["Risk"])
api_router.include_router(registry_router, tags=["Registry"])
if imports_router is not None:
    api_router.include_router(imports_router, tags=["Imports"])
api_router.include_router(gap_analysis_router, tags=["Gap Analysis"])
api_router.include_router(security_router, tags=["Security"])
api_router.include_router(tracing_router, tags=["Tracing"])

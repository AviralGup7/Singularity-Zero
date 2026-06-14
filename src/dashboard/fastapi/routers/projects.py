"""Pre-configured project profiles for quick scan launch."""

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends

from src.dashboard.fastapi.dependencies import require_auth
from src.dashboard.fastapi.schemas import ErrorResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/projects", tags=["Projects"])

CONFIGS_DIR = Path(__file__).resolve().parents[4] / "configs"


def _load_projects() -> list[dict[str, Any]]:
    """Scan configs/ for JSON files with a _project metadata block."""
    projects: list[dict[str, Any]] = []
    if not CONFIGS_DIR.is_dir():
        return projects

    for cfg_path in sorted(CONFIGS_DIR.glob("*.json")):
        try:
            data = json.loads(cfg_path.read_text(encoding="utf-8"))
            meta = data.get("_project")
            if not meta:
                continue
            projects.append(
                {
                    "id": cfg_path.stem,
                    "config_file": cfg_path.name,
                    "name": meta.get("name", cfg_path.stem),
                    "description": meta.get("description", ""),
                    "scope": meta.get("scope", ""),
                    "rewards": meta.get("rewards", ""),
                    "program_url": meta.get("program_url", ""),
                    "exclusions": meta.get("exclusions", []),
                    "rate_limits": meta.get("rate_limits", {}),
                }
            )
        except Exception as exc:
            logger.debug("Skipping %s: %s", cfg_path.name, exc)

    return projects


@router.get(
    "",
    response_model=list[dict[str, Any]],
    responses={401: {"model": ErrorResponse}},
    summary="List project presets",
)
async def list_projects(
    _auth: Any = Depends(require_auth),
) -> list[dict[str, Any]]:
    """Return all available project presets from configs/ directory."""
    return _load_projects()


@router.get(
    "/{project_id}",
    response_model=dict[str, Any],
    responses={
        401: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
    summary="Get project preset details",
)
async def get_project(
    project_id: str,
    _auth: Any = Depends(require_auth),
) -> dict[str, Any]:
    """Return full project preset including config and scope."""
    cfg_path = CONFIGS_DIR / f"{project_id}.json"
    scope_path = CONFIGS_DIR / f"{project_id}_scope.txt"

    if not cfg_path.is_file():
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found")

    data = json.loads(cfg_path.read_text(encoding="utf-8"))
    meta = data.get("_project", {})

    scope_text = ""
    if scope_path.is_file():
        scope_text = scope_path.read_text(encoding="utf-8")

    return {
        "id": project_id,
        "config_file": cfg_path.name,
        "name": meta.get("name", project_id),
        "description": meta.get("description", ""),
        "scope": meta.get("scope", ""),
        "rewards": meta.get("rewards", ""),
        "program_url": meta.get("program_url", ""),
        "exclusions": meta.get("exclusions", []),
        "rate_limits": meta.get("rate_limits", {}),
        "config": data,
        "scope_text": scope_text,
    }

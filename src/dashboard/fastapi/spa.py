"""SPA assets and routing setup for the FastAPI dashboard."""

import logging
import mimetypes
from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)


def setup_mimetypes() -> None:
    """Register standard JavaScript and CSS mimetypes (primarily for Windows compatibility)."""
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("application/javascript", ".mjs")
    mimetypes.add_type("text/css", ".css")


def _safe_file(root: Path, relative: str) -> Path | None:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        return None
    try:
        base = root.resolve()
        candidate = (base / rel).resolve()
        candidate.relative_to(base)
    except (OSError, ValueError):
        return None
    return candidate if candidate.is_file() else None


def setup_spa_routes(app: FastAPI) -> None:
    """Mount static files and define SPA fallback routes."""
    config = app.state.config
    public_root = config.workspace_root / "frontend" / "public"

    def _get_spa_index() -> Response:
        """Helper to serve the SPA index with optimal cache headers."""
        index_path = config.frontend_dist / "index.html"
        if index_path.exists():
            return HTMLResponse(
                content=index_path.read_text(encoding="utf-8"),
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                    "X-Frontend-Version": "3.1.0",
                },
            )

        return HTMLResponse(
            status_code=404,
            content=(
                "<!DOCTYPE html><html>"
                "<body style='background:#0a0a0a;color:#f85149;"
                "padding:2rem;font-family:monospace;'>"
                "<h1>FATAL: Frontend Build Missing</h1>"
                "<p>Built frontend artifacts were not found.</p>"
                "<p>Run: <code>cd frontend && npm install && npm run build"
                "</code></p></body></html>"
            ),
        )

    def _resolve_static(relative: str) -> Path | None:
        found = _safe_file(config.frontend_dist, relative)
        if found is not None:
            return found
        if public_root.exists():
            return _safe_file(public_root, relative)
        return None

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon_svg() -> Response:
        path = _resolve_static("favicon.svg")
        if path is not None:
            return FileResponse(path=path, media_type="image/svg+xml")
        return Response(status_code=204)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon_ico() -> Response:
        path = _resolve_static("favicon.ico") or _resolve_static("favicon.svg")
        if path is not None:
            return FileResponse(path=path)
        return Response(status_code=204)

    @app.get("/manifest.json", include_in_schema=False)
    async def manifest_json() -> Response:
        path = _resolve_static("manifest.json")
        if path is not None:
            return FileResponse(path=path, media_type="application/manifest+json")
        return Response(status_code=204)

    @app.get("/sw.js", include_in_schema=False)
    async def service_worker() -> Response:
        path = _resolve_static("sw.js")
        if path is not None:
            return FileResponse(path=path, media_type="application/javascript")
        return Response(status_code=404)

    if config.frontend_dist.exists():
        assets_dir = config.frontend_dist / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        app.mount(
            "/react",
            StaticFiles(directory=str(config.frontend_dist), html=True),
            name="legacy-compat",
        )

    for mount_name in ("fonts", "night-city"):
        dist_dir = config.frontend_dist / mount_name
        public_dir = public_root / mount_name
        directory = dist_dir if dist_dir.exists() else public_dir
        if directory.exists():
            app.mount(f"/{mount_name}", StaticFiles(directory=str(directory)), name=mount_name)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def root_entry() -> Response:
        return _get_spa_index()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_catch_all(full_path: str) -> Response:
        existing = _resolve_static(full_path)
        if existing is not None:
            return FileResponse(existing)
        normalized = full_path.strip("/")
        if (
            normalized.startswith(("api/", "ws/", "reports/", "_launcher/"))
            or "." in normalized.split("/")[-1]
        ):
            return Response(status_code=404)
        return _get_spa_index()

"""SPA assets and routing setup for the FastAPI dashboard."""

import logging
import mimetypes

from fastapi import FastAPI, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)


def setup_mimetypes() -> None:
    """Register standard JavaScript and CSS mimetypes (primarily for Windows compatibility)."""
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("application/javascript", ".mjs")
    mimetypes.add_type("text/css", ".css")


def setup_spa_routes(app: FastAPI) -> None:
    """Mount static files and define SPA fallback routes."""
    config = app.state.config

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
                    "X-Frontend-Version": "2.0.0-modern",
                },
            )

        return HTMLResponse(
            status_code=404,
            content=(
                "<!DOCTYPE html><html>"
                "<body style='background:#0a0a0a;color:#f85149;"
                "padding:2rem;font-family:monospace;'>"
                "<h1>FATAL: Frontend Build Missing</h1>"
                f"<p>Artifacts not found at: "
                f"<code>{config.frontend_dist}</code></p>"
                "<p>Run: <code>cd frontend && npm install && npm run build"
                "</code></p></body></html>"
            ),
        )

    # Specific static files handlers
    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon_svg() -> Response:
        path = config.frontend_dist / "favicon.svg"
        if path.exists():
            return FileResponse(path=path, media_type="image/svg+xml")
        return Response(status_code=204)

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon_ico() -> Response:
        path = config.frontend_dist / "favicon.ico"
        if not path.exists():
            path = config.frontend_dist / "favicon.svg"
        if path.exists():
            return FileResponse(path=path)
        return Response(status_code=204)

    @app.get("/manifest.json", include_in_schema=False)
    async def manifest_json() -> Response:
        path = config.frontend_dist / "manifest.json"
        if path.exists():
            return FileResponse(path=path, media_type="application/manifest+json")
        return Response(status_code=204)

    @app.get("/sw.js", include_in_schema=False)
    async def service_worker() -> Response:
        path = config.frontend_dist / "sw.js"
        if path.exists():
            return FileResponse(path=path, media_type="application/javascript")
        return Response(status_code=404)

    # Mounting the primary assets directory
    if config.frontend_dist.exists():
        assets_dir = config.frontend_dist / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        # Backward compatibility for /react path
        app.mount(
            "/react",
            StaticFiles(directory=str(config.frontend_dist), html=True),
            name="legacy-compat",
        )

    # SPA Fallback logic
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def root_entry() -> Response:
        return _get_spa_index()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_catch_all(full_path: str) -> Response:
        normalized = full_path.strip("/")
        if (
            normalized.startswith(("api/", "ws/", "reports/", "_launcher/"))
            or "." in normalized.split("/")[-1]
        ):
            return Response(status_code=404)
        return _get_spa_index()

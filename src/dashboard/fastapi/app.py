"""FastAPI application factory for the cyber security dashboard."""

import asyncio
import logging
import mimetypes
import os
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from src.dashboard.fastapi.config import DashboardConfig, FeatureFlags
from src.dashboard.fastapi.middleware import (
    AuditLoggingMiddleware,
    CSRFProtectionMiddleware,
    RequestTimingMiddleware,
    SecurityHeadersMiddleware,
)
from src.dashboard.fastapi.response_validator import ResponseValidationMiddleware
from src.dashboard.fastapi.schemas import (
    DashboardStatsResponse,
    FindingsSummaryResponse,
)
from src.dashboard.fastapi.security import SecurityStore, api_security_enabled, app_secret_key
from src.dashboard.rate_limiter import RateLimitMiddleware
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode
from src.infrastructure.mesh.sharding import MeshShardManager
from src.websocket_server.integration import (
    WSServices,
    integrate_with_pipeline_progress,
    setup_websocket_routes,
)

# Fix for Windows mimetypes
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("application/javascript", ".mjs")
mimetypes.add_type("text/css", ".css")

try:
    import psutil
except ImportError:
    psutil = None



logger = logging.getLogger(__name__)


_START_TIME: float | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Manage application startup and shutdown lifecycle with high-availability considerations."""
    global _START_TIME
    _START_TIME = time.time()

    config: DashboardConfig = app.state.config
    logger.info("Dashboard server starting on %s:%d", config.host, config.port)
    logger.info("Project Root: %s", config.workspace_root)
    logger.info("Frontend Dist: %s", config.frontend_dist)

    from src.infrastructure.cache import CacheManager
    from src.infrastructure.cache.config import CacheConfig

    cache_config = CacheConfig(
        sqlite_db_path=config.cache_db_path,
        cache_dir=config.cache_dir,
        redis_url=config.redis_url,
    )
    app.state.cache_manager = CacheManager(config=cache_config)

    from src.dashboard.fastapi.routers.cache import start_cache_analytics

    app.state.cache_analytics_task = start_cache_analytics(app)

    from src.dashboard.services import DashboardServices

    app.state.services = DashboardServices(
        workspace_root=config.workspace_root,
        output_root=config.output_root,
        config_template=config.config_template,
    )

    # Initialize persistent job store (SQLite)
    db_path = config.output_root / "jobs.db"
    app.state.services.init_persistence(db_path)

    # Set up WebSocket server for real-time communication
    ws_services: WSServices | None = None
    try:
        ws_api_keys = {key: f"admin:{index}" for index, key in enumerate(config.admin_keys) if key}
        ws_required_roles = {"read_only", "worker", "admin"} if api_security_enabled() else None
        ws_services = setup_websocket_routes(
            app,
            jwt_secret=app_secret_key() if api_security_enabled() else (config.api_key if config.api_key else None),
            api_keys=ws_api_keys or None,
            required_roles=ws_required_roles,
            heartbeat_interval=20.0,  # More aggressive heartbeat for faster failure detection
            heartbeat_timeout=45.0,
            max_connections_per_ip=5 if api_security_enabled() else 20,
            redis_url=config.redis_url,  # Enable distributed Pub/Sub fan-out
            redis_channel="cyber-pipeline:ws:broadcast",
        )
        app.state.ws_services = ws_services

        # Integrate WebSocket broadcasting with pipeline progress tracking
        if hasattr(app.state.services, "jobs") and hasattr(app.state.services, "lock"):
            integrate_with_pipeline_progress(
                ws_services,
                job_state_store=app.state.services.jobs,
                lock=app.state.services.lock,
            )
    except Exception as exc:
        logger.warning("WebSocket server initialization failed: %s", exc)
        app.state.ws_services = None

    # 1. Initialize local mesh node identity
    node_id = f"worker-{uuid.uuid4().hex[:8]}"
    local_node = MeshNode(
        id=node_id,
        host=config.host,
        port=config.port,
        status="alive",
        cpu_usage=psutil.cpu_percent() if psutil else 0.0,
        ram_available_mb=psutil.virtual_memory().available / 1024 / 1024 if psutil else 0.0,
        active_jobs=0,
        last_seen=time.time()
    )

    # 2. Start Authenticated Gossip Engine
    mesh_secret = os.getenv("MESH_SECRET", "frontier-default-secret")
    gossip_engine = GossipEngine(local_node, secret=mesh_secret)
    await gossip_engine.start()
    app.state.gossip = gossip_engine

    # 3. Initialize Consistent Hashing Shard Manager
    shard_manager = MeshShardManager()
    shard_manager.add_node(node_id)
    app.state.sharding = shard_manager

    # 3b. Initialize Bloom frontier sync. Redis pub/sub starts only when configured.
    from src.core.frontier.bloom import NeuralBloomFilter
    from src.core.frontier.bloom_mesh import BloomMeshSynchronizer

    bloom_filter = NeuralBloomFilter(
        capacity=int(os.getenv("BLOOM_CAPACITY", "1000000")),
        error_rate=float(os.getenv("BLOOM_ERROR_RATE", "0.001")),
    )
    bloom_mesh = BloomMeshSynchronizer(
        bloom_filter,
        node_id=node_id,
        redis_url=config.redis_url,
    )
    await bloom_mesh.start()
    app.state.bloom_filter = bloom_filter
    app.state.bloom_mesh = bloom_mesh

    # 4. Background telemetry heartbeat for Gossip
    async def _mesh_telemetry_pulse(node: MeshNode, app_ref: FastAPI) -> None:
        while True:
            try:
                if psutil:
                    node.cpu_usage = psutil.cpu_percent()
                    node.ram_available_mb = psutil.virtual_memory().available / 1024 / 1024
                # Filter running jobs
                running = [j for j in app_ref.state.services.jobs.values() if j.get("status") == "running"]
                node.active_jobs = len(running)
                node.last_seen = time.time()
                # Gossip will propagate this on next cycle
                await asyncio.sleep(5.0)
            except Exception as e:
                logger.debug("Mesh telemetry pulse failed: %s", e)
                await asyncio.sleep(10.0)

    asyncio.create_task(_mesh_telemetry_pulse(local_node, app))

    if FeatureFlags.ENABLE_BAYESIAN_ETA():
        from src.dashboard.eta_engine import get_eta_engine
        eta_engine = get_eta_engine()
        await eta_engine.start()

    logger.info("Neural-Mesh Infrastructure: ACTIVE (NodeID: %s)", node_id)
    logger.info("Dashboard lifecyle transition: READY")

    yield

    logger.info("Dashboard lifecyle transition: SHUTDOWN")

    # Graceful termination of active pipeline processes
    if hasattr(app.state, "services") and hasattr(app.state.services, "jobs"):
        for job_id, job in app.state.services.jobs.items():
            if job.get("status") == "running":
                process = job.get("process")
                if process:
                    logger.info("Terminating process for job %s", job_id)
                    process.terminate()

    if ws_services:
        await ws_services.shutdown()

    if hasattr(app.state, "gossip"):
        await app.state.gossip.stop()

    if hasattr(app.state, "cache_analytics_task"):
        app.state.cache_analytics_task.cancel()
        try:
            await app.state.cache_analytics_task
        except asyncio.CancelledError:
            pass

    if hasattr(app.state, "cache_manager"):
        app.state.cache_manager.close()

    if hasattr(app.state, "bloom_mesh"):
        await app.state.bloom_mesh.stop()

    if FeatureFlags.ENABLE_BAYESIAN_ETA():
        from src.dashboard.eta_engine import get_eta_engine
        await get_eta_engine().stop()

    if hasattr(app.state.services, "close_persistence"):
        app.state.services.close_persistence()


def create_app(config: DashboardConfig | None = None) -> FastAPI:
    """Create and configure the production-grade FastAPI application instance."""
    if config is None:
        config = DashboardConfig()

    app = FastAPI(
        title="Cyber Security Test Pipeline Dashboard",
        description="Unified security orchestration and vulnerability analysis dashboard.",
        version="2.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    app.state.config = config
    security_store = SecurityStore(config.security_db_path)
    security_store.init()
    app.state.security_store = security_store

    # ──────────────────────────────────────────────────────────
    # Middleware Configuration
    # ──────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    from src.dashboard.rate_limiter import RateLimitConfig
    security_enabled = api_security_enabled()
    rate_limit_config = RateLimitConfig(
        window_seconds=1.0 if security_enabled else 60.0,
        default_limit=int(os.getenv("RATE_LIMIT_GLOBAL_RPS", "30")) if security_enabled else config.rate_limit_default,
        jobs_limit=2 if security_enabled else config.rate_limit_jobs,
        replay_limit=config.rate_limit_replay,
        redis_url=config.redis_url,
        endpoint_limits={"/api/jobs": 2, "/api/jobs/start": 2} if security_enabled else {},
    )
    app.add_middleware(RateLimitMiddleware, config=rate_limit_config)
    app.add_middleware(CSRFProtectionMiddleware)
    app.add_middleware(RequestTimingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditLoggingMiddleware)
    app.add_middleware(ResponseValidationMiddleware)

    # ──────────────────────────────────────────────────────────
    # API Router Integration
    # ──────────────────────────────────────────────────────────
    from src.dashboard.fastapi.routers import api_router
    app.include_router(api_router)

    def _error_payload(error: str, detail: Any = None, code: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"error": error}
        if detail is not None:
            payload["detail"] = detail
        if code:
            payload["code"] = code
        return payload

    def _record_security_error(request: Request, status_code: int, detail: Any) -> None:
        if status_code < 400:
            return
        event_type = "server_error" if status_code >= 500 else "client_error"
        if status_code in {401, 403}:
            event_type = "invalid_auth"
        app.state.security_store.record_event(
            event_type,
            status_code=status_code,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else "unknown",
            detail=detail if isinstance(detail, str) else str(detail),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        _record_security_error(request, exc.status_code, exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(
                "HTTP Error",
                exc.detail,
                str(exc.status_code),
            ),
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        detail = [
            {
                "loc": e.get("loc", []),
                "path": ".".join(str(part) for part in e.get("loc", [])),
                "type": e.get("type", "value_error"),
                "message": e.get("msg", "Invalid request") if config.debug else "Invalid request",
            }
            for e in exc.errors()
        ]
        _record_security_error(request, 422, detail)
        return JSONResponse(
            status_code=422,
            content=_error_payload("Validation Error", detail, "validation_error"),
        )

    @app.exception_handler(Exception)
    async def internal_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Internal Server Error: %s", exc)
        _record_security_error(request, 500, "Internal Server Error")
        detail = str(exc) if config.debug else "Internal Server Error"
        return JSONResponse(
            status_code=500,
            content=_error_payload("Internal Server Error", detail, "internal_server_error"),
        )

    # ──────────────────────────────────────────────────────────
    # Static Assets & SPA Orchestration
    # ──────────────────────────────────────────────────────────

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
                    "X-Frontend-Version": "2.0.0-modern"
                }
            )

        return HTMLResponse(
            status_code=404,
            content=f"<!DOCTYPE html><html><body style='background:#0a0a0a;color:#f85149;padding:2rem;font-family:monospace;'>"
                    f"<h1>FATAL: Frontend Build Missing</h1><p>Artifacts not found at: <code>{config.frontend_dist}</code></p>"
                    f"<p>Run: <code>cd frontend && npm install && npm run build</code></p></body></html>"
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
        app.mount("/react", StaticFiles(directory=str(config.frontend_dist), html=True), name="legacy-compat")

    # Serve generated artifacts (Reports & Launcher logs)
    @app.get("/_launcher/{job_id}/{filename}", include_in_schema=False)
    async def serve_launcher_artifact(job_id: str, filename: str) -> Response:
        safe_path = (config.workspace_root / "_launcher" / job_id / filename).resolve()
        if safe_path.is_file() and safe_path.is_relative_to(config.workspace_root.resolve()):
            return FileResponse(path=safe_path)
        return Response(status_code=404)

    @app.get("/reports/{target_name:path}/{file_path:path}", include_in_schema=False)
    async def serve_pipeline_report(target_name: str, file_path: str) -> Response:
        base = config.output_root.resolve()
        full_path = (base / target_name / file_path).resolve()
        if full_path.is_file() and full_path.is_relative_to(base):
            return FileResponse(path=full_path)
        return Response(status_code=404)

    # ──────────────────────────────────────────────────────────
    # Primary Application Endpoints
    # ──────────────────────────────────────────────────────────

    @app.get("/api/health/live", tags=["System"])
    async def health_check_live() -> dict[str, Any]:
        return {"status": "ok", "uptime": time.time() - (_START_TIME or time.time())}

    @app.get("/api/dashboard", response_model=DashboardStatsResponse, tags=["Analytics"])
    async def get_dashboard_stats() -> dict[str, Any]:
        """Compute and return global pipeline health and risk metrics."""
        services = app.state.services
        targets = services.list_targets()
        jobs = services.list_jobs()

        weights = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.1}
        total_findings = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        weighted_score = 0.0

        for t in targets:
            cnts = t.get("severity_counts", {})
            for sev, count in cnts.items():
                s_key = sev.lower()
                if s_key in severity_counts:
                    severity_counts[s_key] += count
                    total_findings += count
                    weighted_score += count * weights.get(s_key, 0)

        health_score = max(0.0, 100.0 - min(100.0, weighted_score / max(1, len(targets)) * 2))
        active_jobs = [j for j in jobs if j.get("status") == "running"]

        completed_jobs = sum(1 for j in jobs if j.get("status") == "completed")
        failed_jobs = sum(1 for j in jobs if j.get("status") == "failed")
        health_label = "Healthy" if health_score >= 80 else ("Warning" if health_score >= 50 else "Critical")

        return {
            "total_targets": len(targets),
            "completed_targets": len(targets),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "pipeline_health_score": int(round(health_score)),
            "pipeline_health_label": health_label,
            "active_jobs": len(active_jobs),
            "completed_jobs": completed_jobs,
            "failed_jobs": failed_jobs,
            "avg_progress": int(sum(j.get("progress_percent", 0) for j in active_jobs) / max(1, len(active_jobs))),
            "stage_counts": {
                "recon": sum(1 for j in active_jobs if "recon" in j.get("stage", "").lower()),
                "scanning": sum(1 for j in active_jobs if "scan" in j.get("stage", "").lower()),
                "validation": sum(1 for j in active_jobs if "val" in j.get("stage", "").lower()),
            }
        }

    @app.get("/api/findings", response_model=FindingsSummaryResponse, tags=["Analytics"])
    async def get_findings_summary(target: str | None = None) -> dict[str, Any]:
        services = app.state.services
        findings = services.query.get_all_findings(target_name=target, limit=50)
        summaries = services.query.get_target_summaries()
        return {
            "findings": findings,
            "total_findings": sum(t["finding_count"] for t in summaries),
            "targets": summaries,
            "targets_with_findings": [t["name"] for t in summaries if t["finding_count"] > 0]
        }

    # SPA Fallback logic
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def root_entry() -> Response:
        return _get_spa_index()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_catch_all(full_path: str) -> Response:
        normalized = full_path.strip("/")
        if normalized.startswith(("api/", "ws/", "reports/", "_launcher/")) or "." in normalized.split("/")[-1]:
            return Response(status_code=404)
        return _get_spa_index()

    return app

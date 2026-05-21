"""FastAPI application factory for the cyber security dashboard."""

import asyncio
import logging
import os
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.bloom_mesh import BloomMeshSynchronizer
from src.dashboard.fastapi.collaboration import TriageCollaborationService
from src.dashboard.fastapi.config import DashboardConfig, FeatureFlags
from src.dashboard.fastapi.middleware import (
    AuditLoggingMiddleware,
    CSRFProtectionMiddleware,
    RequestTimingMiddleware,
    SecurityHeadersMiddleware,
)
from src.dashboard.fastapi.response_validator import ResponseValidationMiddleware
from src.dashboard.fastapi.routers import api_router
from src.dashboard.fastapi.schemas import (
    DashboardStatsResponse,
)
from src.dashboard.fastapi.security import SecurityStore, api_security_enabled, app_secret_key
from src.dashboard.fastapi.spa import setup_mimetypes, setup_spa_routes
from src.dashboard.rate_limiter import RateLimitConfig, RateLimitMiddleware
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode
from src.infrastructure.mesh.sharding import MeshShardManager
from src.intelligence.ml.registry import ModelVersionRegistry
from src.pipeline.self_healing import (
    CorrectionEvent,
    CorrectiveAction,
    CorrectiveActionRegistry,
    HealthComponent,
    HealthMetric,
    HealthStatus,
    SelfHealingController,
)
from src.websocket_server.integration import (
    WSServices,
    integrate_with_pipeline_progress,
    setup_websocket_routes,
)

# Fix for Windows mimetypes
setup_mimetypes()

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

    from src.core.plugins.loader import refresh_dynamic_plugins, start_dynamic_plugin_watcher

    refresh_dynamic_plugins()
    start_dynamic_plugin_watcher()

    from src.infrastructure.security.audit import AuditLogger  # pylint: disable=C0415
    from src.infrastructure.security.config import SecurityConfig  # pylint: disable=C0415

    app.state.audit_logger = AuditLogger(SecurityConfig())

    from src.infrastructure.cache import CacheManager  # pylint: disable=C0415
    from src.infrastructure.cache.config import CacheConfig  # pylint: disable=C0415

    cache_config = CacheConfig(
        sqlite_db_path=config.cache_db_path,
        cache_dir=config.cache_dir,
        redis_url=config.redis_url,
    )
    app.state.cache_manager = CacheManager(config=cache_config)

    from src.dashboard.fastapi.routers.cache import start_cache_analytics  # pylint: disable=C0415

    app.state.cache_analytics_task = start_cache_analytics(app)

    from src.dashboard.services import DashboardServices  # pylint: disable=C0415

    app.state.services = DashboardServices(
        workspace_root=config.workspace_root,
        output_root=config.output_root,
        config_template=config.config_template,
    )

    # Initialize persistent job store (SQLite)
    db_path = config.output_root / "jobs.db"
    app.state.services.init_persistence(db_path)
    app.state.triage_collaboration = TriageCollaborationService(config.output_root)

    # Set up WebSocket server for real-time communication
    ws_services: WSServices | None = None
    try:
        ws_api_keys = {key: f"admin:{index}" for index, key in enumerate(config.admin_keys) if key}
        ws_required_roles = {"read_only", "worker", "admin"} if api_security_enabled() else None
        ws_services = setup_websocket_routes(
            app,
            jwt_secret=app_secret_key()
            if api_security_enabled()
            else (config.api_key if config.api_key else None),
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
    except Exception as exc:  # pylint: disable=W0718
        logger.warning("WebSocket server initialization failed: %s", exc)
        app.state.ws_services = None

    # 1. Initialize local mesh node identity
    node_id = f"worker-{uuid.uuid4().hex[:8]}"
    if psutil:
        # Prime the CPU counter
        psutil.cpu_percent(interval=None)

    local_node = MeshNode(
        id=node_id,
        host=config.host,
        port=config.port,
        status="alive",
        cpu_usage=psutil.cpu_percent(interval=0.1) if psutil else 0.0,
        ram_available_mb=psutil.virtual_memory().available / 1024 / 1024 if psutil else 0.0,
        active_jobs=0,
        last_seen=time.time(),
    )

    # 2. Start Authenticated Gossip Engine
    mesh_secret = os.getenv("MESH_SECRET", "frontier-default-secret")
    gossip_engine = GossipEngine(local_node, secret=mesh_secret)
    try:
        await gossip_engine.start()
    except OSError as exc:
        logger.warning("Gossip mesh disabled because UDP bind failed: %s", exc)
        app.state.gossip = None
    else:
        app.state.gossip = gossip_engine

    # 3. Initialize Consistent Hashing Shard Manager
    shard_manager = MeshShardManager()
    shard_manager.add_node(node_id)
    app.state.sharding = shard_manager

    # 3b. Initialize Bloom frontier sync. Redis pub/sub starts only when configured.
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
    app.state.model_registry = ModelVersionRegistry()

    async def _pipeline_stage_probe() -> list[HealthMetric]:
        metrics: list[HealthMetric] = []
        now = time.time()
        jobs = getattr(app.state.services, "jobs", {})
        for job_id, job in list(jobs.items()):
            if job.get("status") != "running":
                continue
            updated = float(
                job.get("updated_at")
                or job.get("last_update")
                or job.get("started_at")
                or now
            )
            age = max(0.0, now - updated)
            metrics.append(
                HealthMetric(
                    component=HealthComponent.PIPELINE_STAGE,
                    name="stage_age_seconds",
                    value=round(age, 2),
                    labels={
                        "job_id": job_id,
                        "stage": job.get("stage", "unknown"),
                        "target": job.get("target", ""),
                    },
                )
            )
        return metrics

    async def _dashboard_connection_probe() -> list[HealthMetric]:
        ws = getattr(app.state, "ws_services", None)
        if ws is None:
            return [
                HealthMetric(
                    component=HealthComponent.DASHBOARD_CONNECTION,
                    name="dashboard_connection_age",
                    value=0,
                    status=HealthStatus.DEGRADED,
                    labels={"reason": "websocket_services_unavailable"},
                )
            ]
        connections = await ws.manager.get_all_connections()
        now = time.time()
        metrics = [
            HealthMetric(
                component=HealthComponent.DASHBOARD_CONNECTION,
                name="dashboard_active_connections",
                value=len(connections),
            )
        ]
        for connection in connections:
            metrics.append(
                HealthMetric(
                    component=HealthComponent.DASHBOARD_CONNECTION,
                    name="dashboard_connection_age",
                    value=round(now - connection.last_activity, 2),
                    labels={"connection_id": connection.connection_id, "user_id": connection.user_id},
                )
            )
        return metrics

    action_registry = CorrectiveActionRegistry()

    async def _refresh_stuck_stage(finding: Any) -> CorrectionEvent:
        job_id = finding.labels.get("job_id")
        jobs = getattr(app.state.services, "jobs", {})
        job = jobs.get(job_id) if job_id else None
        if isinstance(job, dict):
            job["updated_at"] = time.time()
            job["health_recovery"] = {
                "action": "refetch_stage_timeout",
                "reason": finding.reason,
                "at": time.time(),
            }
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=CorrectiveAction.REFRESH_STUCK_STAGE,
            success=job is not None,
            message=f"Refreshed stuck stage watchdog for {job_id or 'unknown job'}",
            component=HealthComponent.PIPELINE_STAGE,
            details={"job_id": job_id},
        )

    async def _flush_bloom(finding: Any) -> CorrectionEvent:
        details = await bloom_mesh.flush_overflowing_filter(reason="self_healing")
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=CorrectiveAction.FLUSH_BLOOM_FILTER,
            success=True,
            message="Flushed saturated Bloom filter and published reconciliation snapshot",
            component=HealthComponent.BLOOM_MESH,
            details=details,
        )

    async def _rollback_model(finding: Any) -> CorrectionEvent:
        registry = app.state.model_registry
        details = registry.rollback_bad_model_version(finding.labels.get("model_name"))
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=CorrectiveAction.ROLLBACK_MODEL_VERSION,
            success=bool(details.get("rolled_back")),
            message=details.get("reason", "Model rollback evaluated"),
            component=HealthComponent.MODEL_REGISTRY,
            details=details,
        )

    async def _escalate(finding: Any) -> CorrectionEvent:
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=CorrectiveAction.ESCALATE_ANALYST,
            success=True,
            message=f"Escalated {finding.component.value}: {finding.reason}",
            component=finding.component,
            details={"labels": finding.labels},
        )

    async def _rebalance(finding: Any) -> CorrectionEvent:
        gossip = getattr(app.state, "gossip", None)
        details = gossip.mesh_health() if gossip else {"mesh": "unavailable"}
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=CorrectiveAction.REBALANCE_ACTORS,
            success=gossip is not None,
            message="Rebalanced actor placement pressure against current mesh telemetry",
            component=finding.component,
            details=details,
        )

    action_registry.register(CorrectiveAction.REFRESH_STUCK_STAGE, _refresh_stuck_stage)
    action_registry.register(CorrectiveAction.FLUSH_BLOOM_FILTER, _flush_bloom)
    action_registry.register(CorrectiveAction.ROLLBACK_MODEL_VERSION, _rollback_model)
    action_registry.register(CorrectiveAction.ESCALATE_ANALYST, _escalate)
    action_registry.register(CorrectiveAction.REBALANCE_ACTORS, _rebalance)

    controller = SelfHealingController(action_registry=action_registry)
    controller.register_probe("pipeline_stages", _pipeline_stage_probe)
    controller.register_probe("dashboard_connections", _dashboard_connection_probe)
    controller.register_probe(
        "bloom_mesh",
        lambda: bloom_mesh.health_metrics(fill_threshold=controller.bloom_fill_threshold),
    )
    controller.register_probe("model_registry", app.state.model_registry.health_metrics)
    app.state.self_healing_controller = controller
    await controller.start()

    # 4. Background telemetry heartbeat for Gossip
    async def _mesh_telemetry_pulse(node: MeshNode, app_ref: FastAPI) -> None:
        while True:
            try:
                if psutil:
                    # Fix S1-1: Use to_thread to avoid blocking the event loop
                    # while getting fresh CPU %
                    node.cpu_usage = await asyncio.to_thread(psutil.cpu_percent, interval=0.1)
                    node.ram_available_mb = psutil.virtual_memory().available / 1024 / 1024
                # Filter running jobs
                running = [
                    j for j in app_ref.state.services.jobs.values() if j.get("status") == "running"
                ]
                node.active_jobs = len(running)
                node.last_seen = time.time()
                # Gossip will propagate this on next cycle
                await asyncio.sleep(5.0)
            except Exception as e:  # pylint: disable=W0718
                logger.debug("Mesh telemetry pulse failed: %s", e)
                await asyncio.sleep(10.0)

    asyncio.create_task(_mesh_telemetry_pulse(local_node, app))

    if FeatureFlags.ENABLE_BAYESIAN_ETA():
        from src.dashboard.eta_engine import get_eta_engine  # pylint: disable=C0415

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

    if getattr(app.state, "gossip", None) is not None:
        await app.state.gossip.stop()

    if hasattr(app.state, "cache_analytics_task"):
        app.state.cache_analytics_task.cancel()
        try:
            await app.state.cache_analytics_task
        except asyncio.CancelledError:
            pass

    if hasattr(app.state, "cache_manager"):
        app.state.cache_manager.close()

    if hasattr(app.state, "self_healing_controller"):
        await app.state.self_healing_controller.stop()

    if hasattr(app.state, "bloom_mesh"):
        await app.state.bloom_mesh.stop()

    if FeatureFlags.ENABLE_BAYESIAN_ETA():
        from src.dashboard.eta_engine import get_eta_engine  # pylint: disable=C0415

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

    security_enabled = api_security_enabled()
    rate_limit_config = RateLimitConfig(
        window_seconds=1.0 if security_enabled else 60.0,
        default_limit=int(os.getenv("RATE_LIMIT_GLOBAL_RPS", "30"))
        if security_enabled
        else config.rate_limit_default,
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
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
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

    # SPA assets and fallback routes setup will be handled at the end of app creation


    # ──────────────────────────────────────────────────────────
    # Primary Application Endpoints
    # ──────────────────────────────────────────────────────────

    @app.get("/api/health/live", tags=["System"])
    async def health_check_live() -> dict[str, Any]:
        return {"status": "ok", "uptime": time.time() - (_START_TIME or time.time())}

    @app.get("/api/health/ready", tags=["System"])
    async def health_check_ready() -> dict[str, Any]:
        """Readiness probe with subsystem checks."""
        subsystems: dict[str, str] = {}
        subsystems["websocket"] = "up" if getattr(app.state, "ws_services", None) else "down"
        subsystems["gossip"] = "up" if getattr(app.state, "gossip", None) else "down"
        subsystems["cache"] = "up" if getattr(app.state, "cache_manager", None) else "down"
        subsystems["bloom"] = "up" if getattr(app.state, "bloom_filter", None) else "down"
        all_up = all(v == "up" for v in subsystems.values())
        return {
            "status": "ready" if all_up else "degraded",
            "subsystems": subsystems,
            "uptime": time.time() - (_START_TIME or time.time()),
        }

    @app.get("/api/version", tags=["System"])
    async def get_version() -> dict[str, Any]:
        """Return build and runtime version metadata."""
        return {
            "version": "2.0.0",
            "build": os.getenv("BUILD_SHA", "dev"),
            "python": f"{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}.{__import__('sys').version_info.micro}",
            "boot_time": _START_TIME,
            "uptime_seconds": round(time.time() - (_START_TIME or time.time()), 1),
        }

    @app.websocket("/ws/triage/{run_id}")
    async def ws_triage(websocket: Any, run_id: str) -> None:
        from src.dashboard.fastapi.routers.triage import handle_triage_websocket

        service = getattr(app.state, "triage_collaboration", None)
        if service is None:
            service = TriageCollaborationService(config.output_root)
            app.state.triage_collaboration = service
        await handle_triage_websocket(websocket, run_id, service)

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
        health_label = (
            "Healthy" if health_score >= 80 else ("Warning" if health_score >= 50 else "Critical")
        )

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
            "avg_progress": int(
                sum(j.get("progress_percent", 0) for j in active_jobs) / max(1, len(active_jobs))
            ),
            "stage_counts": {
                "discovery": sum(
                    1
                    for j in active_jobs
                    if "subdomain" in j.get("stage", "").lower()
                    or "recon" in j.get("stage", "").lower()
                ),
                "collection": sum(
                    1
                    for j in active_jobs
                    if "urls" in j.get("stage", "").lower() or "scan" in j.get("stage", "").lower()
                ),
                "analysis": sum(1 for j in active_jobs if "analysis" in j.get("stage", "").lower()),
                "validation": sum(1 for j in active_jobs if "val" in j.get("stage", "").lower()),
                "reporting": sum(1 for j in active_jobs if "report" in j.get("stage", "").lower()),
                "other": sum(
                    1
                    for j in active_jobs
                    if not any(
                        k in j.get("stage", "").lower()
                        for k in ["subdomain", "recon", "url", "scan", "analysis", "val", "report"]
                    )
                ),
            },
        }

    # SPA Fallback and static assets setup
    setup_spa_routes(app)

    return app

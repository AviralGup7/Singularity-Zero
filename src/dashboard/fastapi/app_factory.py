"""FastAPI application factory for the cyber security dashboard."""

import asyncio
import logging
import os
import sys
import time
from typing import Any, cast

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.core.exceptions import (
    CircuitBreakerOpenError,
    DatabaseUnavailableError,
    PipelineError,
    RedisDegradedError,
    ToolNotInstalledError,
)
from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.dependencies import require_admin
from src.dashboard.fastapi.lifespan import lifespan
from src.dashboard.fastapi.middleware_setup import setup_middleware
from src.dashboard.fastapi.router_setup import setup_routers
from src.dashboard.fastapi.schemas import DashboardStatsResponse
from src.dashboard.fastapi.security_setup import setup_security_store
from src.dashboard.fastapi.spa import setup_spa_routes

_dashboard_stats_lock = asyncio.Lock()
logger = logging.getLogger(__name__)


def create_app(config: DashboardConfig | None = None) -> FastAPI:
    if config is None:
        config = DashboardConfig()

    # Production safety guard: refuse SQLite in production (Finding #44)
    if os.getenv("APP_ENV") == "production":
        db_url = os.getenv("DATABASE_URL", "")
        if "sqlite" in db_url.lower():
            raise RuntimeError(
                "SQLite is not supported in production deployments. "
                "Set DATABASE_URL to a PostgreSQL connection string."
            )

    # Production safety guard: enforce all production security requirements
    from src.core.security.secret_validator import enforce_production_security

    enforce_production_security()

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
    setup_security_store(app, config)
    setup_middleware(app, config)
    setup_routers(app, config)

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
        security_store = getattr(app.state, "security_store", None)
        if security_store is not None:
            security_store.record_event(
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
            content=_error_payload("HTTP Error", exc.detail, str(exc.status_code)),
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
            status_code=422, content=_error_payload("Validation Error", detail, "validation_error")
        )

    @app.exception_handler(ToolNotInstalledError)
    async def tool_not_installed_handler(
        request: Request, exc: ToolNotInstalledError
    ) -> JSONResponse:
        _record_security_error(request, 503, str(exc))
        return JSONResponse(
            status_code=503,
            content=_error_payload(
                "Tool Not Installed",
                {"message": str(exc), "tool": exc.tool, "code": exc.error_code},
                exc.error_code,
            ),
        )

    @app.exception_handler(CircuitBreakerOpenError)
    async def circuit_breaker_open_handler(
        request: Request, exc: CircuitBreakerOpenError
    ) -> JSONResponse:
        _record_security_error(request, 503, str(exc))
        return JSONResponse(
            status_code=503,
            content=_error_payload(
                "Circuit Breaker Open",
                {
                    "message": str(exc),
                    "tool": exc.tool,
                    "breaker_state": exc.breaker_state,
                    "code": exc.error_code,
                },
                exc.error_code,
            ),
        )

    @app.exception_handler(DatabaseUnavailableError)
    async def database_unavailable_handler(
        request: Request, exc: DatabaseUnavailableError
    ) -> JSONResponse:
        _record_security_error(request, 503, str(exc))
        return JSONResponse(
            status_code=503,
            content=_error_payload(
                "Database Unavailable",
                {"message": str(exc), "code": exc.error_code},
                exc.error_code,
            ),
        )

    @app.exception_handler(RedisDegradedError)
    async def redis_degraded_handler(request: Request, exc: RedisDegradedError) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content=_error_payload(
                "Service Degraded",
                {"message": str(exc), "code": exc.error_code},
                exc.error_code,
            ),
            headers={"Retry-After": "10"},
        )

    @app.exception_handler(PipelineError)
    async def pipeline_error_handler(request: Request, exc: PipelineError) -> JSONResponse:
        _record_security_error(request, 500, str(exc))
        return JSONResponse(
            status_code=500,
            content=_error_payload(
                "Pipeline Error",
                {"message": exc.message, "details": exc.details},
                "pipeline_error",
            ),
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

    @app.get("/api/health/live", tags=["System"])
    async def health_check_live() -> dict[str, Any]:
        from src.dashboard.fastapi.lifespan import _START_TIME

        return {"status": "ok", "uptime": time.time() - (_START_TIME or time.time())}

    @app.get("/api/health/ready", tags=["System"])
    async def health_check_ready() -> dict[str, Any]:
        subsystems: dict[str, str] = {}
        degraded_reasons: list[str] = []

        subsystems["websocket"] = "up" if getattr(app.state, "ws_services", None) else "down"
        subsystems["gossip"] = "up" if getattr(app.state, "gossip", None) else "down"
        subsystems["bloom"] = "up" if getattr(app.state, "bloom_filter", None) else "down"

        cache_manager = getattr(app.state, "cache_manager", None)
        if cache_manager is not None:
            try:
                cache_stats = cache_manager.get_stats()
                backend_type = getattr(cache_stats, "backend_type", "") if cache_stats else ""
                if "memory" in str(backend_type).lower():
                    subsystems["cache"] = "degraded"
                    degraded_reasons.append("Using in-memory fallback (Redis unavailable)")
                else:
                    subsystems["cache"] = "up"
            except Exception:
                subsystems["cache"] = "up"
        else:
            subsystems["cache"] = "down"
            degraded_reasons.append("Cache not initialized")

        subsystems["database"] = "up"
        subsystems["tools"] = "up"

        all_up = all(v == "up" for v in subsystems.values())
        any_down = any(v == "down" for v in subsystems.values())

        if all_up:
            status = "ready"
        elif any_down:
            status = "degraded"
        else:
            status = "degraded"

        from src.dashboard.fastapi.lifespan import _START_TIME

        return {
            "status": status,
            "subsystems": subsystems,
            "degraded_reasons": degraded_reasons,
            "uptime": time.time() - (_START_TIME or time.time()),
        }

    @app.get("/api/version", tags=["System"])
    async def get_version() -> dict[str, Any]:
        from src.dashboard.fastapi.lifespan import _START_TIME

        return {
            "version": "2.0.0",
            "build": os.getenv("BUILD_SHA", "dev"),
            "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "boot_time": _START_TIME,
            "uptime_seconds": round(time.time() - (_START_TIME or time.time()), 1),
        }

    @app.get("/metrics", tags=["System"], dependencies=[Depends(require_admin)])
    async def get_metrics(request: Request) -> Any:
        try:
            from fastapi import Response
            from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

            registry_metrics = generate_latest()
            try:
                from src.infrastructure.observability.metrics import (
                    get_metrics as get_cyber_metrics,
                )

                central_text = get_cyber_metrics().expose_prometheus()
                combined = (
                    registry_metrics + b"\n" + central_text.encode("utf-8")
                    if registry_metrics
                    else central_text.encode("utf-8")
                )
            except Exception:  # noqa: BLE001
                combined = registry_metrics
                logger.debug("Failed to merge cyber metrics with prometheus metrics")
            return Response(content=combined, media_type=CONTENT_TYPE_LATEST)
        except ImportError:
            from fastapi import Response

            from src.infrastructure.observability.metrics import get_metrics as get_cyber_metrics

            central_text = get_cyber_metrics().expose_prometheus()
            return Response(
                content=central_text.encode("utf-8")
                if central_text
                else b"# prometheus_client not installed",
                media_type="text/plain",
            )

    @app.websocket("/ws/triage/{run_id}")
    async def ws_triage(websocket: Any, run_id: str) -> None:
        from src.dashboard.fastapi.collaboration import TriageCollaborationService
        from src.dashboard.fastapi.routers.triage import handle_triage_websocket

        service = getattr(app.state, "triage_collaboration", None)
        if service is None:
            service = TriageCollaborationService(config.output_root)
            app.state.triage_collaboration = service
        await handle_triage_websocket(websocket, run_id, service)

    @app.get("/api/dashboard", response_model=DashboardStatsResponse, tags=["Analytics"])
    async def get_dashboard_stats() -> dict[str, Any]:
        now = time.time()
        cache_manager = getattr(app.state, "cache_manager", None)
        if cache_manager is not None:
            cached = cache_manager.get("dashboard_stats", namespace="analytics")
            if cached is not None:
                return cast(dict[str, Any], cached)
        else:
            async with _dashboard_stats_lock:
                cached = getattr(app.state, "cached_dashboard_stats", None)
                cache_time = getattr(app.state, "dashboard_stats_cache_time", 0.0)
                if cached is not None and now - cache_time < 5.0:
                    return cast(dict[str, Any], cached)

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

        unique_target_names = {t.get("name") for t in targets if t.get("name")}
        active_jobs = [j for j in jobs if j.get("status") == "running"]
        active_targets = {j.get("target") for j in active_jobs if j.get("target")}

        all_targets = unique_target_names.union(active_targets)
        total_targets = len(all_targets)
        completed_targets = max(0, total_targets - len(active_targets))

        health_score = max(
            0.0, 100.0 - min(100.0, weighted_score / max(1, len(unique_target_names)) * 2)
        )
        completed_jobs = sum(1 for j in jobs if j.get("status") == "completed")
        failed_jobs = sum(1 for j in jobs if j.get("status") == "failed")
        health_label = (
            "Healthy" if health_score >= 80 else ("Warning" if health_score >= 50 else "Critical")
        )

        stats = {
            "total_targets": total_targets,
            "completed_targets": completed_targets,
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

        if cache_manager is not None:
            cache_manager.set("dashboard_stats", stats, ttl=5, namespace="analytics")
        else:
            async with _dashboard_stats_lock:
                app.state.cached_dashboard_stats = stats
                app.state.dashboard_stats_cache_time = now
        return stats

    from pydantic import BaseModel

    class FrontendTelemetryEvent(BaseModel):
        event_type: str
        payload: dict[str, Any] | None = None

    _TELEMETRY_PAYLOAD_ALLOWLIST: set[str] = {
        "page_view",
        "button_click",
        "error",
        "performance",
        "feature_usage",
        "session_duration",
        "load_time",
        "render_time",
        "api_latency",
    }

    @app.post("/api/telemetry", tags=["Analytics"])
    async def report_frontend_telemetry(event: FrontendTelemetryEvent) -> dict[str, Any]:
        try:
            from src.infrastructure.observability.metrics import get_metrics as _get_metrics

            _reg = _get_metrics()
            _reg.counter("frontend_events_total", labels={"event_type": event.event_type}).inc()
            if event.payload:
                for key, value in event.payload.items():
                    if key not in _TELEMETRY_PAYLOAD_ALLOWLIST:
                        continue
                    if isinstance(value, (int, float)):
                        _reg.counter("frontend_payload_" + key).inc(value)
        except Exception:
            logger.debug("Failed to record frontend telemetry event", exc_info=True)
            pass
        return {"status": "accepted", "event_type": event.event_type}

    setup_spa_routes(app)
    return app

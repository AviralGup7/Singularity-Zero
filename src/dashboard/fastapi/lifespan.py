"""Lifespan events for the FastAPI dashboard."""

import asyncio
import logging
import os
import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from src.core.events import get_event_bus
from src.core.frontier.bloom_mesh import ReconcileBloom
from src.core.security.secret_validator import validate_or_raise
from src.dashboard.fastapi.collaboration import TriageCollaborationService
from src.dashboard.fastapi.config import DashboardConfig
from src.dashboard.fastapi.feature_flags import FeatureFlags
from src.dashboard.fastapi.mesh_setup import init_bloom_filter, init_bloom_mesh
from src.dashboard.fastapi.self_healing_setup import setup_self_healing_controller
from src.dashboard.fastapi.spa import setup_mimetypes
from src.dashboard.fastapi.ws_setup import setup_websocket
from src.infrastructure.mesh.gossip import GossipEngine, MeshNode
from src.infrastructure.mesh.sharding import MeshShardManager
from src.infrastructure.observability.health_subscriber import register_health_subscriber
from src.pipeline.self_healing import (
    CorrectionEvent,
    CorrectiveAction,
    CorrectiveActionRegistry,
    HealthComponent,
)
from src.websocket_server.integration import (
    WSServices,
    integrate_with_pipeline_progress,
)

try:
    import psutil
except ImportError:
    psutil = None

setup_mimetypes()

logger = logging.getLogger(__name__)

_START_TIME: float | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    global _START_TIME
    _START_TIME = time.time()

    from src.core.plugins.loader import refresh_dynamic_plugins, start_dynamic_plugin_watcher
    from src.dashboard.fastapi.process_lock import ProcessLifespanLock
    from src.dashboard.fastapi.routers.cache import start_cache_analytics
    from src.dashboard.fastapi.security import api_security_enabled, app_secret_key
    from src.dashboard.services import DashboardServices
    from src.infrastructure.cache import CacheManager
    from src.infrastructure.cache.config import CacheConfig
    from src.infrastructure.security.audit import AuditLogger
    from src.infrastructure.security.config import SecurityConfig
    from src.pipeline.services.tool_execution import ToolExecutionService

    config: DashboardConfig = app.state.config
    logger.info("Dashboard server starting on %s:%d", config.host, config.port)
    logger.info("Project Root: %s", config.workspace_root)
    logger.info("Frontend Dist: %s", config.frontend_dist)

    validate_or_raise()

    refresh_dynamic_plugins()
    start_dynamic_plugin_watcher()

    app.state.audit_logger = AuditLogger(SecurityConfig())

    cache_config = CacheConfig(
        sqlite_db_path=config.cache_db_path,
        cache_dir=config.cache_dir,
        redis_url=config.redis_url,
    )
    app.state.cache_manager = CacheManager(config=cache_config)

    app.state.cache_analytics_task = start_cache_analytics(app)

    app.state.services = DashboardServices(
        workspace_root=config.workspace_root,
        output_root=config.output_root,
        config_template=config.config_template,
    )
    app.state.services.cache_manager = app.state.cache_manager

    lock_path = config.output_root / "startup.lock"
    app.state.lifespan_lock = ProcessLifespanLock(str(lock_path))
    is_primary = app.state.lifespan_lock.acquire()

    db_path = config.output_root / "jobs.db"
    app.state.services.init_persistence(db_path, is_primary=is_primary)
    app.state.triage_collaboration = TriageCollaborationService(config.output_root)

    ws_services: WSServices | None = None
    try:
        ws_api_keys = {key: f"admin:{index}" for index, key in enumerate(config.admin_keys) if key}
        ws_required_roles = {"read_only", "worker", "admin"} if api_security_enabled() else None
        ws_services = setup_websocket(
            app,
            jwt_secret=app_secret_key() if api_security_enabled() else (config.api_key if config.api_key else None),
            api_keys=ws_api_keys or None,
            required_roles=ws_required_roles,
            heartbeat_interval=20.0,
            heartbeat_timeout=45.0,
            max_connections_per_ip=5 if api_security_enabled() else 20,
            redis_url=config.redis_url,
            redis_channel="cyber-pipeline:ws:broadcast",
        )
        app.state.ws_services = ws_services

        if hasattr(app.state.services, "jobs") and hasattr(app.state.services, "lock"):
            integrate_with_pipeline_progress(
                ws_services,
                job_state_store=app.state.services.jobs,
                lock=app.state.services.lock,
            )
    except Exception as exc:
        logger.warning("WebSocket server initialization failed: %s", exc)
        app.state.ws_services = None

    node_id = f"worker-{uuid.uuid4().hex[:8]}"
    if psutil:
        psutil.cpu_percent(interval=None)

    local_node = MeshNode(
        id=node_id,
        host=os.getenv("MESH_BIND_INTERFACE", config.host),
        port=config.port,
        status="alive",
        cpu_usage=psutil.cpu_percent(interval=0.1) if psutil else 0.0,
        ram_available_mb=psutil.virtual_memory().available / 1024 / 1024 if psutil else 0.0,
        active_jobs=0,
        last_seen=time.time(),
    )

    import secrets

    mesh_secret = os.getenv("MESH_SECRET")
    is_prod = os.getenv("APP_ENV") == "production"

    if not mesh_secret:
        if is_prod:
            raise ValueError(
                "CRITICAL SECURITY RISK: MESH_SECRET environment variable is required in production."
            )
        mesh_secret = secrets.token_hex(32)
        logger.warning(
            "MESH_SECRET is not set; generated a per-process random secret. "
            "Mesh peers will NOT be able to authenticate each other. "
            "Set MESH_SECRET to a long, random, shared value in any environment "
            "with more than one dashboard instance."
        )
    elif is_prod and mesh_secret in (
        "frontier-default-secret",
        "frontier-default-secret-change-in-prod",
        "frontier-default-secret-change-me",
    ):
        raise ValueError(
            "CRITICAL SECURITY RISK: MESH_SECRET must not be a default value in production."
        )

    gossip_engine = GossipEngine(local_node, secret=mesh_secret)
    try:
        await gossip_engine.start()
    except OSError as exc:
        logger.warning("Gossip mesh disabled because UDP bind failed: %s", exc)
        app.state.gossip = None
    else:
        app.state.gossip = gossip_engine

    shard_manager = MeshShardManager()
    shard_manager.add_node(node_id)
    app.state.sharding = shard_manager

    bloom_filter = init_bloom_filter()
    bloom_mesh = init_bloom_mesh(bloom_filter, node_id=node_id, redis_url=config.redis_url)
    await bloom_mesh.start()
    app.state.bloom_filter = bloom_filter
    app.state.bloom_mesh = bloom_mesh
    app.state.bloom_reconciler = ReconcileBloom(bloom_mesh)
    app.state.model_registry = _init_model_registry()

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
        details = await app.state.bloom_reconciler.flush(reason="self_healing")
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

    async def _trip_tool_breaker(finding: Any) -> CorrectionEvent:
        controller = app.state.self_healing_controller
        labels = dict(finding.labels or {})
        tool_name = labels.get("tool")
        if not tool_name and finding.metric.startswith("tool_circuit_breaker_state."):
            tool_name = finding.metric.split(".", 1)[1]
        if not tool_name and finding.metric.startswith("tool_error_rate."):
            tool_name = finding.metric.split(".", 1)[1]
        if not tool_name:
            return CorrectionEvent(
                finding_id=finding.finding_id,
                action=CorrectiveAction.TRIP_TOOL_CIRCUIT_BREAKER,
                success=False,
                message="Unable to derive tool name from finding",
                component=finding.component,
                details={"reason": finding.reason, "labels": labels},
            )
        success = controller.force_open_tool_breaker(
            tool_name,
            reason=f"self_healing:{finding.reason}",
            duration_seconds=None,
        )
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=CorrectiveAction.TRIP_TOOL_CIRCUIT_BREAKER,
            success=success,
            message=f"Force-opened circuit breaker for {tool_name}" if success else f"Unable to trip breaker for {tool_name}",
            component=finding.component,
            details={"reason": finding.reason, "labels": labels, "tool": tool_name},
        )

    action_registry.register(CorrectiveAction.TRIP_TOOL_CIRCUIT_BREAKER, _trip_tool_breaker)

    tool_service: ToolExecutionService = getattr(app.state, "tool_execution_service", None) or ToolExecutionService()
    app.state.tool_execution_service = tool_service

    controller = setup_self_healing_controller(action_registry=action_registry)
    controller.register_probe("pipeline_stages", _pipeline_stage_probe)  # noqa: F821
    controller.register_probe("dashboard_connections", _dashboard_connection_probe)  # noqa: F821
    controller.register_probe(
        "bloom_mesh",
        lambda: bloom_mesh.health_metrics(fill_threshold=controller.bloom_fill_threshold),
    )
    controller.register_probe("model_registry", app.state.model_registry.health_metrics)
    controller.bind_tool_execution_service(tool_service)
    app.state.self_healing_controller = controller
    register_health_subscriber(get_event_bus(), controller)

    async def _mesh_telemetry_pulse(node: MeshNode, app_ref: FastAPI) -> None:
        while True:
            try:
                if psutil is not None:
                    try:
                        node.cpu_usage = await asyncio.to_thread(psutil.cpu_percent, interval=0.1)
                        node.ram_available_mb = psutil.virtual_memory().available / 1024 / 1024
                    except (AttributeError, OSError) as psutil_exc:
                        logger.debug("psutil metric read failed: %s", psutil_exc)
                running = [j for j in app_ref.state.services.jobs.values() if j.get("status") == "running"]
                node.active_jobs = len(running)
                node.last_seen = time.time()
                await asyncio.sleep(5.0)
            except Exception as e:
                logger.debug("Mesh telemetry pulse failed: %s", e)
                await asyncio.sleep(10.0)

    app.state.mesh_telemetry_task = asyncio.create_task(_mesh_telemetry_pulse(local_node, app))

    if FeatureFlags.ENABLE_BAYESIAN_ETA():
        from src.dashboard.feature_flags_setup import maybe_start_bayesian_eta
        maybe_start_bayesian_eta()

    logger.info("Neural-Mesh Infrastructure: ACTIVE (NodeID: %s)", node_id)
    logger.info("Dashboard lifecycle transition: READY")
    if psutil is None:
        logger.warning("psutil is not installed; mesh CPU/RAM telemetry will be unavailable")

    yield

    logger.info("Dashboard lifecycle transition: SHUTDOWN")

    if hasattr(app.state, "mesh_telemetry_task"):
        app.state.mesh_telemetry_task.cancel()
        try:
            await app.state.mesh_telemetry_task
        except asyncio.CancelledError:
            pass

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
        from src.dashboard.eta_engine import get_eta_engine
        await get_eta_engine().stop()

    if hasattr(app.state.services, "close_persistence"):
        app.state.services.close_persistence()

    if hasattr(app.state, "lifespan_lock"):
        app.state.lifespan_lock.release()


def _init_model_registry() -> Any:
    from src.intelligence.ml.registry import ModelVersionRegistry
    return ModelVersionRegistry()

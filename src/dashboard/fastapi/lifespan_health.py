"""Phase 5: Health monitoring, self-healing, telemetry."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi import FastAPI

from src.core.contracts.health import (
    CorrectionEvent,
    CorrectiveAction,
    HealthComponent,
    HealthMetric,
    HealthStatus,
)
from src.dashboard.fastapi.self_healing_setup import setup_self_healing_controller
from src.infrastructure.mesh.gossip import MeshNode
from src.infrastructure.observability.health_subscriber import register_health_subscriber
from src.websocket_server.integration import WSServices

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)


async def startup_health(
    app: FastAPI,
    local_node: MeshNode,
    node_id: str,
    ws_services: WSServices | None,
) -> None:
    """Health monitoring, self-healing, telemetry."""
    from src.core.contracts.protocol_registry import (
        get_corrective_action_registry_cls,
        get_tool_execution_service_cls,
    )
    from src.core.events import get_event_bus

    _registry_cls = get_corrective_action_registry_cls()
    if _registry_cls is None:
        raise RuntimeError("CorrectiveActionRegistry not registered at startup")
    action_registry = _registry_cls()

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
            message=f"Force-opened circuit breaker for {tool_name}"
            if success
            else f"Unable to trip breaker for {tool_name}",
            component=finding.component,
            details={"reason": finding.reason, "labels": labels, "tool": tool_name},
        )

    action_registry.register(CorrectiveAction.TRIP_TOOL_CIRCUIT_BREAKER, _trip_tool_breaker)

    tool_service = getattr(app.state, "tool_execution_service", None)
    if tool_service is None:
        _service_cls = get_tool_execution_service_cls()
        if _service_cls is not None:
            tool_service = _service_cls()
        else:
            logger.warning("ToolExecutionService not registered at startup")
            tool_service = None
    app.state.tool_execution_service = tool_service

    async def _pipeline_stage_probe() -> list[HealthMetric]:
        jobs = getattr(app.state.services, "jobs", {})
        now = time.time()
        metrics = [
            HealthMetric(
                component=HealthComponent.PIPELINE_STAGE,
                name="stage_count",
                value=len(jobs),
            )
        ]
        for job_id, job in list(jobs.items()):
            if job.get("status") != "running":
                continue
            updated = float(
                job.get("updated_at") or job.get("last_update") or job.get("started_at") or now
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
                    labels={
                        "connection_id": connection.connection_id,
                        "user_id": connection.user_id,
                    },
                )
            )
        return metrics

    controller = setup_self_healing_controller(action_registry=action_registry)
    controller.register_probe("pipeline_stages", _pipeline_stage_probe)
    controller.register_probe("dashboard_connections", _dashboard_connection_probe)
    controller.register_probe(
        "bloom_mesh",
        lambda: app.state.bloom_mesh.health_metrics(fill_threshold=controller.bloom_fill_threshold),
    )
    if getattr(app.state, "model_registry", None) is not None:
        controller.register_probe("model_registry", app.state.model_registry.health_metrics)
    else:
        logger.debug("Model registry not available; skipping model_registry health probe")
    controller.bind_tool_execution_service(tool_service)
    app.state.self_healing_controller = controller
    register_health_subscriber(get_event_bus(), controller)

    async def _mesh_telemetry_pulse(node: MeshNode, app_ref: FastAPI) -> None:
        """Periodically refresh local hardware telemetry and mesh state.

        Bug #4: Added circuit breaker to prevent infinite failure loops.
        After ``_MAX_CONSECUTIVE_FAILURES`` consecutive failures, the loop
        logs an error and exits instead of retrying forever.  The counter
        resets on each successful iteration.
        """
        _MAX_CONSECUTIVE_FAILURES = 20
        _consecutive_failures = 0

        while True:
            try:
                if psutil is not None:
                    try:
                        node.cpu_usage = await asyncio.to_thread(psutil.cpu_percent, interval=0.1)
                        node.ram_available_mb = psutil.virtual_memory().available / 1024 / 1024
                    except (AttributeError, OSError) as psutil_exc:
                        logger.debug("psutil metric read failed: %s", psutil_exc)
                running = [
                    j for j in app_ref.state.services.jobs.values() if j.get("status") == "running"
                ]
                node.active_jobs = len(running)
                node.last_seen = time.time()

                try:
                    from src.infrastructure.observability.metrics import get_metrics as _get_metrics

                    _reg = _get_metrics()
                    _reg.gauge("active_workers").set(len(running))
                    _reg.gauge("queue_depth").set(
                        sum(
                            1
                            for j in app_ref.state.services.jobs.values()
                            if j.get("status") == "queued"
                        )
                    )
                    if psutil is not None:
                        _reg.gauge("cpu_usage_percent").set(psutil.cpu_percent(interval=0))
                        _reg.gauge("memory_usage_mb").set(
                            psutil.virtual_memory().used / 1024 / 1024
                        )
                except Exception:
                    logger.debug("Failed to update mesh telemetry gauges", exc_info=True)
                    pass

                _consecutive_failures = 0
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                _consecutive_failures += 1
                if _consecutive_failures >= _MAX_CONSECUTIVE_FAILURES:
                    logger.error(
                        "Mesh telemetry pulse failed %d consecutive times (%s). "
                        "Circuit breaker tried — telemetry task exiting.",
                        _consecutive_failures,
                        e,
                    )
                    return
                logger.debug(
                    "Mesh telemetry pulse failed (%d/%d): %s",
                    _consecutive_failures,
                    _MAX_CONSECUTIVE_FAILURES,
                    e,
                )
                await asyncio.sleep(10.0)

    # Bug #3: Use TaskRegistry for all task creation to consolidate ownership.
    # Previously used asyncio.create_task() + LifecycleManager.register_task(),
    # which created dual-ownership ambiguity.
    try:
        from src.core.task_registry import get_task_registry
        app.state.mesh_telemetry_task = get_task_registry().create_task(
            _mesh_telemetry_pulse(local_node, app),
            owner="mesh_telemetry",
            name="telemetry_pulse",
        )
    except ImportError:
        app.state.mesh_telemetry_task = asyncio.create_task(
            _mesh_telemetry_pulse(local_node, app)
        )
        try:
            from src.core.lifecycle import get_lifecycle_manager
            get_lifecycle_manager().register_task(
                "mesh_telemetry", app.state.mesh_telemetry_task
            )
        except ImportError:
            logger.warning("Operation failed in lifespan_health.py", exc_info=True)

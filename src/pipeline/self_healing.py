"""Autonomous health controller for long-running pipeline scans."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any

from src.core.contracts.health import (
    CorrectionEvent,
    CorrectiveAction,
    HealthComponent,
    HealthFinding,
    HealthMetric,
    HealthStatus,
    PipelineHealthSnapshot,
)
from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

Probe = Callable[[], Awaitable[list[HealthMetric]] | list[HealthMetric]]
ActionHandler = Callable[[HealthFinding], Awaitable[CorrectionEvent] | CorrectionEvent]


class CorrectiveActionRegistry:
    """Maps health findings to bounded corrective actions."""

    def __init__(self) -> None:
        self._handlers: dict[CorrectiveAction, ActionHandler] = {}
        self._history: list[CorrectionEvent] = []

    @property
    def history(self) -> list[CorrectionEvent]:
        return list(self._history)

    def register(self, action: CorrectiveAction, handler: ActionHandler) -> None:
        self._handlers[action] = handler

    async def execute(self, finding: HealthFinding) -> CorrectionEvent:
        handler = self._handlers.get(finding.action)
        event: CorrectionEvent | None = None
        if handler is None:
            event = CorrectionEvent(
                finding_id=finding.finding_id,
                action=CorrectiveAction.ESCALATE_ANALYST,
                success=False,
                message=f"No corrective handler registered for {finding.action.value}",
                component=finding.component,
                details={"reason": finding.reason, "labels": finding.labels},
            )
        else:
            try:
                result = handler(finding)
                event = await result if inspect.isawaitable(result) else result
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.exception("Self-healing action %s failed", finding.action.value)
                event = CorrectionEvent(
                    finding_id=finding.finding_id,
                    action=finding.action,
                    success=False,
                    message=str(exc),
                    component=finding.component,
                    details={"reason": finding.reason, "labels": finding.labels},
                )
        if event is None:
            event = CorrectionEvent(
                finding_id=finding.finding_id,
                action=finding.action,
                success=False,
                message="Handler failed to return correction event",
                component=finding.component,
                details={"reason": finding.reason, "labels": finding.labels},
            )
        self._history.append(event)
        del self._history[:-100]
        return event


class SelfHealingController:
    """Polls subsystem health and runs corrective actions without operator input."""

    def __init__(
        self,
        *,
        interval_seconds: float = 15.0,
        stale_stage_seconds: float = 900.0,
        queue_depth_threshold: int = 5000,
        worker_heartbeat_timeout: float = 60.0,
        bloom_fill_threshold: float = 0.92,
        dashboard_connection_timeout: float = 75.0,
        action_registry: CorrectiveActionRegistry | None = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.stale_stage_seconds = stale_stage_seconds
        self.queue_depth_threshold = queue_depth_threshold
        self.worker_heartbeat_timeout = worker_heartbeat_timeout
        self.bloom_fill_threshold = bloom_fill_threshold
        self.dashboard_connection_timeout = dashboard_connection_timeout
        self.actions = action_registry or CorrectiveActionRegistry()
        self._probes: dict[str, Probe] = {}
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._last_snapshot = PipelineHealthSnapshot(
            status=HealthStatus.UNKNOWN,
            metrics=[],
            findings=[],
            corrections=[],
        )

    @property
    def last_snapshot(self) -> PipelineHealthSnapshot:
        return self._last_snapshot

    def register_probe(self, name: str, probe: Probe) -> None:
        self._probes[name] = probe

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="self-healing-controller")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def evaluate_once(self) -> PipelineHealthSnapshot:
        metrics = await self._collect_metrics()
        findings = self._classify(metrics)
        corrections: list[CorrectionEvent] = []
        for finding in findings:
            if finding.action != CorrectiveAction.NOOP:
                corrections.append(await self.actions.execute(finding))
        status = self._overall_status(metrics, findings, corrections)
        self._last_snapshot = PipelineHealthSnapshot(
            status=status,
            metrics=metrics,
            findings=findings,
            corrections=[*self.actions.history[-20:]],
        )
        return self._last_snapshot

    async def _run_loop(self) -> None:
        while self._running:
            try:
                await self.evaluate_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # pylint: disable=broad-exception-caught
                logger.exception("Self-healing controller evaluation failed")
            await asyncio.sleep(self.interval_seconds)

    async def _collect_metrics(self) -> list[HealthMetric]:
        metrics: list[HealthMetric] = []
        for name, probe in list(self._probes.items()):
            try:
                result = probe()
                probe_metrics = await result if inspect.isawaitable(result) else result
                metrics.extend(probe_metrics)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                metrics.append(
                    HealthMetric(
                        component=HealthComponent.PIPELINE_STAGE,
                        name=f"{name}.probe_error",
                        value=1,
                        status=HealthStatus.DEGRADED,
                        labels={"error": str(exc)},
                    )
                )
        return metrics

    def _classify(self, metrics: list[HealthMetric]) -> list[HealthFinding]:
        findings: list[HealthFinding] = []
        for metric in metrics:
            status = metric.status
            if status in (HealthStatus.OK, HealthStatus.UNKNOWN):
                status = self._derive_status(metric)
            if status == HealthStatus.OK:
                continue
            findings.append(self._finding_for_metric(metric, status))
        return findings

    def _derive_status(self, metric: HealthMetric) -> HealthStatus:
        if (
            metric.name.endswith("queue_depth")
            and float(metric.value or 0) > self.queue_depth_threshold
        ):
            return HealthStatus.DEGRADED
        if (
            metric.name.endswith("worker_heartbeat_age")
            and float(metric.value or 0) > self.worker_heartbeat_timeout
        ):
            return HealthStatus.CRITICAL
        if (
            metric.name.endswith("stage_age_seconds")
            and float(metric.value or 0) > self.stale_stage_seconds
        ):
            return HealthStatus.DEGRADED
        if (
            metric.name.endswith("bloom_fill_ratio")
            and float(metric.value or 0) > self.bloom_fill_threshold
        ):
            return HealthStatus.CRITICAL
        if (
            metric.name.endswith("dashboard_connection_age")
            and float(metric.value or 0) > self.dashboard_connection_timeout
        ):
            return HealthStatus.DEGRADED
        if metric.name.endswith("model_error_rate") and float(metric.value or 0) > float(
            metric.threshold or 0.2
        ):
            return HealthStatus.CRITICAL
        return HealthStatus.OK

    def _finding_for_metric(self, metric: HealthMetric, status: HealthStatus) -> HealthFinding:
        action = CorrectiveAction.NOOP
        if metric.component == HealthComponent.QUEUE:
            action = CorrectiveAction.RELEASE_STALE_LEASE
        elif metric.component == HealthComponent.WORKER:
            action = CorrectiveAction.RESTART_WORKER
        elif metric.component in (HealthComponent.GHOST_ACTOR, HealthComponent.EXECUTION_ENGINE):
            action = CorrectiveAction.REBALANCE_ACTORS
        elif metric.component == HealthComponent.BLOOM_MESH:
            action = CorrectiveAction.FLUSH_BLOOM_FILTER
        elif metric.component == HealthComponent.MODEL_REGISTRY:
            action = CorrectiveAction.ROLLBACK_MODEL_VERSION
        elif metric.component == HealthComponent.PIPELINE_STAGE:
            action = CorrectiveAction.REFRESH_STUCK_STAGE
        elif metric.component == HealthComponent.DASHBOARD_CONNECTION:
            action = CorrectiveAction.ESCALATE_ANALYST

        return HealthFinding(
            component=metric.component,
            status=status,
            reason=f"{metric.name} is {metric.value}",
            action=action,
            metric=metric.name,
            labels=metric.labels,
        )

    @staticmethod
    def _overall_status(
        metrics: list[HealthMetric],
        findings: list[HealthFinding],
        corrections: list[CorrectionEvent],
    ) -> HealthStatus:
        if any(f.status == HealthStatus.CRITICAL for f in findings):
            if corrections and any(event.success for event in corrections):
                return HealthStatus.RECOVERING
            return HealthStatus.CRITICAL
        if findings:
            return HealthStatus.DEGRADED
        if metrics:
            return HealthStatus.OK
        return HealthStatus.UNKNOWN


def _dataclass_to_dict(value: Any) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for field_name in getattr(value, "__dataclass_fields__", {}):
        raw = getattr(value, field_name)
        data[field_name] = raw.value if isinstance(raw, StrEnum) else raw
    return data

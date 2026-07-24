"""Autonomous health controller for long-running pipeline scans."""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from src.core.contracts.health import (
    CorrectionEvent,
    CorrectiveAction,
    CorrectiveActionRegistry,
    HealthComponent,
    HealthFinding,
    HealthMetric,
    HealthStatus,
    PipelineHealthSnapshot,
)
from src.core.events import EventBus, EventType, get_event_bus
from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.self_healing_events import push_health_metric

if TYPE_CHECKING:
    from src.infrastructure.notifications.manager import NotificationManager
    from src.pipeline.self_healing.dampening import DampeningWindow
    from src.pipeline.self_healing.history_store import CorrectionHistoryStore

logger = get_pipeline_logger(__name__)

Probe = Callable[[], Awaitable[list[HealthMetric]] | list[HealthMetric]]


class _CircuitBreakerBridge(Protocol):
    def force_open_breaker(
        self,
        tool_name: str,
        reason: str,
        duration_seconds: float | None = ...,
    ) -> Any: ...

    def reset_breaker(self, tool_name: str) -> Any: ...

    def breaker_snapshot(self) -> dict[str, Any]: ...

    def consume_pending_probes(self) -> dict[str, Callable[[Any], None]]: ...


class SelfHealingController:
    """Reactive health controller that runs corrective actions in response to events.

    The controller is a stateless event processor: subsystem probes publish
    :class:`HealthMetric` events onto the :class:`EventBus`, this controller
    subscribes to them, classifies each metric, and dispatches corrective
    actions through its :class:`CorrectiveActionRegistry`. There is no
    internal polling loop; probe cadence is owned by the subsystems (or by
    callers invoking :meth:`collect_probe_metrics` on demand).
    """

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
        config: Any | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self._config = config
        self.interval_seconds = interval_seconds
        if config is not None:
            self.stale_stage_seconds = float(
                getattr(config, "stale_stage_seconds", stale_stage_seconds)
            )
            self.queue_depth_threshold = int(
                getattr(config, "queue_depth_threshold", queue_depth_threshold)
            )
            self.worker_heartbeat_timeout = float(
                getattr(config, "worker_heartbeat_timeout", worker_heartbeat_timeout)
            )
            self.bloom_fill_threshold = float(
                getattr(config, "bloom_fill_threshold", bloom_fill_threshold)
            )
            self.dashboard_connection_timeout = float(
                getattr(config, "dashboard_connection_timeout", dashboard_connection_timeout)
            )
        else:
            self.stale_stage_seconds = stale_stage_seconds
            self.queue_depth_threshold = queue_depth_threshold
            self.worker_heartbeat_timeout = worker_heartbeat_timeout
            self.bloom_fill_threshold = bloom_fill_threshold
            self.dashboard_connection_timeout = dashboard_connection_timeout
        self.actions = action_registry or CorrectiveActionRegistry()
        self._probes: dict[str, tuple[Probe, EventBus]] = {}
        self._last_snapshot = PipelineHealthSnapshot(
            status=HealthStatus.UNKNOWN,
            metrics=[],
            findings=[],
            corrections=[],
        )
        # Circuit-breaker bridge (optional). When set, the controller emits
        # HealthMetrics for every known tool and can call force_open_breaker
        # in response to sustained-error findings.
        self._breaker_bridge: _CircuitBreakerBridge | None = None
        self._tool_error_rate_threshold: float = float(
            getattr(config, "tool_error_rate_threshold", 0.5) if config is not None else 0.5
        )
        self._tool_failure_count_threshold: int = int(
            getattr(config, "tool_failure_count_threshold", 3) if config is not None else 3
        )
        from src.pipeline.self_healing.dampening import DampeningWindow
        from src.pipeline.self_healing.history_store import CorrectionHistoryStore

        self._dampening_window = DampeningWindow()
        self._history_store = CorrectionHistoryStore()
        self._notification_manager: NotificationManager | None = None
        self._event_bus: EventBus = event_bus or get_event_bus()
        self._event_subscription_id: str | None = None
        self._running = False

    @property
    def dampening_window(self) -> DampeningWindow:
        return self._dampening_window

    @property
    def history_store(self) -> CorrectionHistoryStore:
        return self._history_store

    @property
    def last_snapshot(self) -> PipelineHealthSnapshot:
        return self._last_snapshot

    def register_probe(
        self,
        name: str,
        probe: Probe,
        *,
        event_bus: EventBus | None = None,
    ) -> None:
        """Register a probe that yields ``HealthMetric`` objects on demand.

        The controller no longer polls probes; it forwards each ``HealthMetric``
        returned by a probe to the :class:`EventBus` as a
        :attr:`EventType.HEALTH_METRIC_EMITTED` event. Subsystems that already
        publish their own metrics can keep their callable signature; the
        ``event_bus`` argument controls which bus receives the emitted events.
        """
        self._probes[name] = (probe, event_bus or self._event_bus)

    def bind_tool_execution_service(self, service: _CircuitBreakerBridge) -> None:
        self._breaker_bridge = service

    def bind_notification_manager(self, manager: NotificationManager | None) -> None:
        self._notification_manager = manager

    def subscribe_event_bus(self, event_bus: EventBus | None = None) -> str:
        """Subscribe the controller to ``HEALTH_METRIC_EMITTED`` events."""
        bus = event_bus or self._event_bus
        self._event_bus = bus
        if self._event_subscription_id is not None:
            bus.unsubscribe(self._event_subscription_id)
        subscription_id = bus.subscribe_async(
            EventType.HEALTH_METRIC_EMITTED, self._on_health_metric_event
        )
        self._event_subscription_id = subscription_id
        return subscription_id

    async def _on_health_metric_event(self, event: Any) -> None:
        data = getattr(event, "data", {}) or {}
        if not data:
            return
        try:
            raw_comp = data.get("component_name") or data.get("component", "")
            comp = raw_comp if isinstance(raw_comp, HealthComponent) else HealthComponent(str(raw_comp))
            raw_status = data.get("status", HealthStatus.OK.value)
            status = raw_status if isinstance(raw_status, HealthStatus) else HealthStatus(str(raw_status))
            metric = HealthMetric(
                component=comp,
                name=data.get("metric_name") or data.get("name", ""),
                value=data.get("value"),
                threshold=data.get("threshold"),
                status=status,
                labels=data.get("labels", {}),
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("Ignoring malformed health metric event: %s", exc)
            return
        await self._process_push_metric(metric)

    async def _process_push_metric(self, metric: HealthMetric) -> None:
        status = metric.status
        if status in (HealthStatus.OK, HealthStatus.UNKNOWN):
            status = self._derive_status(metric)
        if status == HealthStatus.OK:
            return
        finding = self._finding_for_metric(metric, status)
        corrective_action = self._resolve_action(finding.action)
        if corrective_action == CorrectiveAction.NOOP:
            return
        if self._dampening_window.should_suppress(corrective_action, finding.component):
            logger.debug(
                "Suppressing dampened corrective action %s for %s",
                corrective_action.value,
                finding.component.value,
            )
            return
        correction = await self.actions.execute(finding)
        self._history_store.record(correction.action, correction.success)
        self._dampening_window.record_fire(corrective_action, finding.component)
        if correction.success and self._history_store.should_escalate(corrective_action):
            degraded_finding = HealthFinding(
                component=finding.component,
                status=HealthStatus.CRITICAL,
                reason=f"Success rate for {corrective_action.value} degraded; escalating to analyst.",
                action=CorrectiveAction.ESCALATE_ANALYST,
                metric=finding.metric,
                labels={"autodegraded": "true", "original_action": corrective_action.value},
            )
            correction = await self.actions.execute(degraded_finding)
        await self._maybe_notify(finding, correction)
        self._last_snapshot = PipelineHealthSnapshot(
            status=status,
            metrics=[metric],
            findings=[finding],
            corrections=[correction, *self.actions.history[-19:]],
        )

    async def start(self) -> None:
        """Subscribe the controller to the event bus.

        The controller no longer spawns a polling task; the call simply
        wires the ``HEALTH_METRIC_EMITTED`` subscription. Subsystems (or
        callers invoking :meth:`collect_probe_metrics`) own probe cadence.
        """
        if self._running:
            return
        self._running = True
        self.subscribe_event_bus()

    async def stop(self) -> None:
        """Tear down the event-bus subscription.

        No background tasks are owned by the controller, so stopping only
        requires unsubscribing the ``HEALTH_METRIC_EMITTED`` handler.
        """
        self._running = False
        if self._event_subscription_id and self._event_bus is not None:
            try:
                self._event_bus.unsubscribe(self._event_subscription_id)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.debug("Failed to unsubscribe health metric listener: %s", exc)
            self._event_subscription_id = None

    async def collect_probe_metrics(self) -> list[HealthMetric]:
        """Invoke every registered probe and publish its metrics as events.

        Each probe returns a list of :class:`HealthMetric`; this coroutine
        fans them out to the bus as ``HEALTH_METRIC_EMITTED`` events so the
        reactive controller (and any other subscriber) can process them
        uniformly. Circuit-breaker metrics are emitted through the same
        channel via :meth:`_collect_breaker_metrics`.
        """
        collected: list[HealthMetric] = []
        for name, (probe, bus) in list(self._probes.items()):
            correlation_id = str(uuid.uuid4())
            try:
                result = probe()
                probe_metrics = await result if inspect.isawaitable(result) else result
            except Exception as exc:  # pylint: disable=broad-exception-caught
                error_metric = HealthMetric(
                    component=HealthComponent.PIPELINE_STAGE,
                    name=f"{name}.probe_error",
                    value=1,
                    status=HealthStatus.DEGRADED,
                    labels={"error": str(exc)},
                )
                push_health_metric(
                    error_metric,
                    source=name,
                    event_bus=bus,
                    correlation_id=correlation_id,
                )
                collected.append(error_metric)
                continue
            for metric in probe_metrics:
                push_health_metric(
                    metric,
                    source=name,
                    event_bus=bus,
                    correlation_id=correlation_id,
                )
                collected.append(metric)
        for metric in self._collect_breaker_metrics():
            push_health_metric(metric, source="circuit_breakers", event_bus=self._event_bus)
            collected.append(metric)
        return collected

    async def evaluate_once(self) -> PipelineHealthSnapshot:
        """Run a one-shot reactive evaluation pass.

        Probes are invoked, their metrics emitted as events, and the bus is
        flushed so the subscriber has fully processed them before the
        snapshot is returned. Useful for ad-hoc dashboard refreshes and
        synchronous tests; production cadence is event-driven, not polled.
        """
        await self.collect_probe_metrics()
        await self._event_bus.flush_pending()
        return self._last_snapshot

    def _resolve_action(self, action: CorrectiveAction) -> CorrectiveAction:
        if action == CorrectiveAction.NOOP:
            return CorrectiveAction.NOOP
        return action

    async def _maybe_notify(
        self, finding: HealthFinding, correction: CorrectionEvent | None
    ) -> None:
        manager = self._notification_manager
        if manager is None:
            return
        try:
            await manager.send_self_healing_alert(finding, correction)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("Self-healing notification dispatch failed: %s", exc)

    def _collect_breaker_metrics(self) -> list[HealthMetric]:
        if self._breaker_bridge is None:
            return []
        metrics: list[HealthMetric] = []
        try:
            snapshot = self._breaker_bridge.breaker_snapshot()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("breaker snapshot probe failed: %s", exc)
            return []

        # Bug fix: Aggregate all open breakers into a single metric instead
        # of emitting one per tool. This prevents notification storms where
        # N failing tools generate N findings, N notifications, and N webhook
        # calls simultaneously.
        open_tools: list[str] = []
        half_open_tools: list[str] = []

        for tool_name, stats in snapshot.items():
            if hasattr(stats, "state"):
                state_value = stats.state
                failure_count = getattr(stats, "failure_count", 0)
                total_failures = getattr(stats, "total_failures", 0)
                total_successes = getattr(stats, "total_successes", 0)
                recovery_timeout = getattr(stats, "recovery_timeout", 0.0)
                forced = getattr(stats, "forced_open", False)
            else:  # tolerate plain-dict snapshots
                state_value = stats.get("state", "closed")
                failure_count = stats.get("failure_count", 0)
                total_failures = stats.get("total_failures", 0)
                total_successes = stats.get("total_successes", 0)
                recovery_timeout = stats.get("recovery_timeout", 0.0)
                forced = stats.get("forced_open", False)

            if state_value == "open":
                open_tools.append(tool_name)
            elif state_value == "half_open":
                half_open_tools.append(tool_name)

            # Still emit per-tool error rate metrics (low frequency, no notifications)
            denom = total_failures + total_successes
            rate = (total_failures / denom) if denom else 0.0
            metrics.append(
                HealthMetric(
                    component=HealthComponent.TOOL_EXECUTION,
                    name=f"tool_error_rate.{tool_name}",
                    value=round(rate, 4),
                    status=HealthStatus.OK,
                    threshold=self._tool_error_rate_threshold,
                    labels={"tool": tool_name},
                )
            )

        # Emit a single aggregated breaker metric for the self-healing pipeline
        if open_tools or half_open_tools:
            worst_status = HealthStatus.CRITICAL if open_tools else HealthStatus.RECOVERING
            metrics.append(
                HealthMetric(
                    component=HealthComponent.TOOL_EXECUTION,
                    name="tool_circuit_breakers_aggregate",
                    value=f"{len(open_tools)}_open_{len(half_open_tools)}_half_open",
                    status=worst_status,
                    threshold=0,
                    labels={
                        "open_tools": ",".join(sorted(open_tools)),
                        "half_open_tools": ",".join(sorted(half_open_tools)),
                        "total_open": str(len(open_tools)),
                        "total_half_open": str(len(half_open_tools)),
                    },
                )
            )

        return metrics

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
        if metric.name.startswith("tool_circuit_breaker_state.") and metric.value == "open":
            return HealthStatus.CRITICAL
        if metric.name.startswith("tool_circuit_breaker_state.") and metric.value == "half_open":
            return HealthStatus.RECOVERING
        if metric.name.startswith("tool_error_rate.") and float(metric.value or 0) > float(
            metric.threshold or self._tool_error_rate_threshold
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
        elif metric.component == HealthComponent.TOOL_EXECUTION:
            action = CorrectiveAction.TRIP_TOOL_CIRCUIT_BREAKER

        return HealthFinding(
            component=metric.component,
            status=status,
            reason=f"{metric.name} is {metric.value}",
            action=action,
            metric=metric.name,
            labels=metric.labels,
        )

    def consume_recovery_probes(self) -> dict[str, Callable[[Any], None]]:
        if self._breaker_bridge is None:
            return {}
        try:
            return dict(self._breaker_bridge.consume_pending_probes())
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("breaker consume_pending_probes failed: %s", exc)
            return {}

    def force_open_tool_breaker(
        self,
        tool_name: str,
        reason: str,
        duration_seconds: float | None = None,
    ) -> bool:
        if self._breaker_bridge is None:
            return False
        try:
            self._breaker_bridge.force_open_breaker(
                tool_name,
                reason,
                duration_seconds=duration_seconds,
            )
            return True
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning("force_open_breaker(%s) failed: %s", tool_name, exc)
            return False


def _dataclass_to_dict(value: Any) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for field_name in getattr(value, "__dataclass_fields__", {}):
        raw = getattr(value, field_name)
        data[field_name] = raw.value if isinstance(raw, StrEnum) else raw
    return data

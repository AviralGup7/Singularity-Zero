from __future__ import annotations

from src.core.events import EventBus, EventType, PipelineEvent
from src.infrastructure.observability.metrics import get_metrics


def register_event_metrics_subscribers(event_bus: EventBus) -> None:
    """Attach telemetry subscribers that derive metrics from domain events."""

    if bool(getattr(event_bus, "_telemetry_metrics_subscribed", False)):
        return

    metrics = get_metrics()

    stage_counter = metrics.counter(
        "pipeline_stage_events_total",
        "Pipeline stage lifecycle events emitted from event bus",
    )
    finding_counter = metrics.counter(
        "pipeline_findings_created_total",
        "Total findings emitted via finding_created events",
    )
    failure_counter = metrics.counter(
        "pipeline_failures_total",
        "Total pipeline failures emitted via pipeline_error events",
    )
    stage_duration = metrics.histogram(
        "pipeline_stage_duration_seconds",
        "Stage duration observed from stage_completed events",
    )

    def _on_stage_started(event: PipelineEvent) -> None:
        if event.data.get("_telemetry_bound"):
            return
        stage_counter.inc()

    def _on_stage_completed(event: PipelineEvent) -> None:
        if event.data.get("_telemetry_bound"):
            return
        stage_counter.inc()
        contract = event.data.get("contract", {})
        duration_seconds = float(contract.get("duration_seconds", 0.0) or 0.0)
        if duration_seconds > 0:
            stage_duration.observe(duration_seconds)

    def _on_stage_failed(event: PipelineEvent) -> None:
        if event.data.get("_telemetry_bound"):
            return
        stage_counter.inc()
        failure_counter.inc()

    def _on_finding_created(event: PipelineEvent) -> None:
        if event.data.get("_telemetry_bound"):
            return
        finding_counter.inc(float(event.data.get("new_findings", 1) or 1))

    def _on_pipeline_error(event: PipelineEvent) -> None:
        if event.data.get("_telemetry_bound"):
            return
        failure_counter.inc()

    event_bus.subscribe(EventType.STAGE_STARTED, _on_stage_started)
    event_bus.subscribe(EventType.STAGE_COMPLETED, _on_stage_completed)
    event_bus.subscribe(EventType.STAGE_FAILED, _on_stage_failed)
    event_bus.subscribe(EventType.FINDING_CREATED, _on_finding_created)
    event_bus.subscribe(EventType.PIPELINE_ERROR, _on_pipeline_error)
    setattr(event_bus, "_telemetry_metrics_subscribed", True)

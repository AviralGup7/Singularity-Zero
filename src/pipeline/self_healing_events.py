"""Event schema, helpers, and EventBus subscription hooks for self-healing."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.core.contracts.health import (
    HealthComponent,
    HealthMetric,
    HealthStatus,
)
from src.core.events import EventType, PipelineEvent, get_event_bus

logger = logging.getLogger(__name__)

_EVENT_TYPE = "health_metric"


@dataclass(slots=True)
class HealthMetricEvent:
    component_name: HealthComponent
    metric_name: str
    value: float | int | str | bool | None
    threshold: float | int | str | bool | None = None
    status: HealthStatus = HealthStatus.OK
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    labels: dict[str, Any] = field(default_factory=dict)

    def to_pipeline_event(self, source: str = "self_healing") -> PipelineEvent:
        data = {
            "component_name": self.component_name.value,
            "metric_name": self.metric_name,
            "value": self.value,
            "threshold": self.threshold,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "labels": self.labels or {},
        }
        return PipelineEvent(
            event_type=EventType.FINDING_DETECTED,
            source=source,
            data=data,
        )


def push_health_metric(metric: HealthMetric, source: str = "self_healing") -> PipelineEvent:
    bus = get_event_bus()
    event = HealthMetricEvent(
        component_name=metric.component,
        metric_name=metric.name,
        value=metric.value,
        threshold=metric.threshold,
        status=metric.status,
        labels=metric.labels,
    ).to_pipeline_event(source=source)
    bus.publish(event)
    logger.debug(
        "Pushed health metric event: %s.%s = %r [%s]",
        metric.component.value,
        metric.name,
        metric.value,
        metric.status.value,
    )
    return event

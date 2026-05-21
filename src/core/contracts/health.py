"""Health status and telemetry contract models for autonomous system monitoring."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class HealthStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    RECOVERING = "recovering"
    UNKNOWN = "unknown"


class HealthComponent(StrEnum):
    PIPELINE_STAGE = "pipeline_stage"
    QUEUE = "queue"
    WORKER = "worker"
    BLOOM_MESH = "bloom_mesh"
    GHOST_ACTOR = "ghost_actor"
    MODEL_REGISTRY = "model_registry"
    DASHBOARD_CONNECTION = "dashboard_connection"
    EXECUTION_ENGINE = "execution_engine"


class CorrectiveAction(StrEnum):
    REFRESH_STUCK_STAGE = "refresh_stuck_stage"
    RELEASE_STALE_LEASE = "release_stale_lease"
    RESTART_WORKER = "restart_worker"
    REBALANCE_ACTORS = "rebalance_actors"
    FLUSH_BLOOM_FILTER = "flush_bloom_filter"
    ROLLBACK_MODEL_VERSION = "rollback_model_version"
    ESCALATE_ANALYST = "escalate_analyst"
    NOOP = "noop"


@dataclass(slots=True)
class HealthMetric:
    component: HealthComponent
    name: str
    value: float | int | str | bool | None
    status: HealthStatus = HealthStatus.OK
    threshold: float | int | None = None
    labels: dict[str, Any] = field(default_factory=dict)
    observed_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class HealthFinding:
    component: HealthComponent
    status: HealthStatus
    reason: str
    action: CorrectiveAction
    metric: str
    labels: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    observed_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class CorrectionEvent:
    finding_id: str
    action: CorrectiveAction
    success: bool
    message: str
    component: HealthComponent
    details: dict[str, Any] = field(default_factory=dict)
    executed_at: float = field(default_factory=time.time)


def _dataclass_to_dict(value: Any) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for field_name in getattr(value, "__dataclass_fields__", {}):
        raw = getattr(value, field_name)
        data[field_name] = raw.value if isinstance(raw, StrEnum) else raw
    return data


@dataclass(slots=True)
class PipelineHealthSnapshot:
    status: HealthStatus
    metrics: list[HealthMetric]
    findings: list[HealthFinding]
    corrections: list[CorrectionEvent]
    generated_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "generated_at": self.generated_at,
            "metrics": [_dataclass_to_dict(metric) for metric in self.metrics],
            "findings": [_dataclass_to_dict(finding) for finding in self.findings],
            "corrections": [_dataclass_to_dict(event) for event in self.corrections],
        }

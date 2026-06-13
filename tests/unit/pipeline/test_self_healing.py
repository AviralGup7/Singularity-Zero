from __future__ import annotations

import pytest

from src.core.events import EventBus, EventType
from src.core.frontier.bloom import NeuralBloomFilter
from src.infrastructure.frontier.bloom_mesh import BloomMeshSynchronizer
from src.infrastructure.observability.health_subscriber import register_health_subscriber
from src.intelligence.ml.registry import ModelVersion, ModelVersionRegistry
from src.pipeline.self_healing import (
    CorrectionEvent,
    CorrectiveAction,
    CorrectiveActionRegistry,
    HealthComponent,
    HealthMetric,
    HealthStatus,
    SelfHealingController,
)


@pytest.mark.asyncio
async def test_controller_reacts_to_health_metric_event() -> None:
    """The controller processes HealthMetric events emitted onto the bus."""
    registry = CorrectiveActionRegistry()
    handled: list[str] = []

    async def refresh(finding):
        handled.append(finding.labels["job_id"])
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=CorrectiveAction.REFRESH_STUCK_STAGE,
            success=True,
            message="refreshed",
            component=HealthComponent.PIPELINE_STAGE,
        )

    registry.register(CorrectiveAction.REFRESH_STUCK_STAGE, refresh)

    bus = EventBus()
    controller = SelfHealingController(
        stale_stage_seconds=1.0,
        action_registry=registry,
        event_bus=bus,
    )
    register_health_subscriber(bus, controller)
    controller.register_probe(
        "stages",
        lambda: [
            HealthMetric(
                component=HealthComponent.PIPELINE_STAGE,
                name="stage_age_seconds",
                value=10.0,
                labels={"job_id": "job-1"},
            )
        ],
        event_bus=bus,
    )

    await controller.collect_probe_metrics()
    await bus.flush_pending()

    snapshot = controller.last_snapshot
    assert snapshot.status == HealthStatus.DEGRADED
    assert handled == ["job-1"]
    assert snapshot.corrections[-1].action == CorrectiveAction.REFRESH_STUCK_STAGE


@pytest.mark.asyncio
async def test_register_health_subscriber_unsubscribes_on_stop() -> None:
    """The subscriber can be cleanly torn down without leaking handlers."""
    registry = CorrectiveActionRegistry()
    bus = EventBus()
    controller = SelfHealingController(
        stale_stage_seconds=1.0,
        action_registry=registry,
        event_bus=bus,
    )
    subscriber = register_health_subscriber(bus, controller)

    assert bus._get_handlers(EventType.HEALTH_METRIC_EMITTED)  # pylint: disable=protected-access
    subscriber.stop()
    assert (  # pylint: disable=protected-access
        not bus._get_handlers(EventType.HEALTH_METRIC_EMITTED)
    )


@pytest.mark.asyncio
async def test_bloom_mesh_flush_resets_saturated_filter() -> None:
    bloom = NeuralBloomFilter(capacity=10, error_rate=0.1)
    bloom.add_many([f"https://example.test/{idx}" for idx in range(30)])
    mesh = BloomMeshSynchronizer(bloom, node_id="node-a")

    before = bloom.get_stats()["element_count"]
    result = await mesh.flush_overflowing_filter()

    assert before > 0
    assert result["status"] == "flushed"
    assert bloom.get_stats()["element_count"] == 0
    assert bloom.get_stats()["fill_ratio"] == 0.0


def test_model_registry_rolls_back_bad_active_version() -> None:
    registry = ModelVersionRegistry(max_error_rate=0.1)
    registry.register(ModelVersion(name="severity", version="1.0.0"))
    registry.register(ModelVersion(name="severity", version="2.0.0"))
    registry.record_health("severity", error_rate=0.5)

    metrics = registry.health_metrics()
    rollback = registry.rollback_bad_model_version("severity")

    assert metrics[0].status == HealthStatus.CRITICAL
    assert rollback["rolled_back"] is True
    assert registry.snapshot()["active"]["severity"]["version"] == "1.0.0"

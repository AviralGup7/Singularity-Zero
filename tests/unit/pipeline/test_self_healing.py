from __future__ import annotations

import pytest

from src.core.frontier.bloom import NeuralBloomFilter
from src.core.frontier.bloom_mesh import BloomMeshSynchronizer
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
async def test_controller_executes_action_for_stale_stage() -> None:
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
    controller = SelfHealingController(
        stale_stage_seconds=1.0,
        action_registry=registry,
    )
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
    )

    snapshot = await controller.evaluate_once()

    assert snapshot.status == HealthStatus.DEGRADED
    assert handled == ["job-1"]
    assert snapshot.corrections[-1].action == CorrectiveAction.REFRESH_STUCK_STAGE


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


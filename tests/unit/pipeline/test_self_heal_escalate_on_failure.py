"""Regression: repeated failed corrections must escalate to an analyst."""

from __future__ import annotations

import pytest

from src.core.events import EventBus
from src.pipeline.self_healing import (
    CorrectionEvent,
    CorrectiveAction,
    CorrectiveActionRegistry,
    HealthComponent,
    HealthMetric,
    SelfHealingController,
)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_controller_escalates_after_repeated_failures() -> None:
    registry = CorrectiveActionRegistry()
    seen: list[CorrectiveAction] = []

    async def handler(finding):
        seen.append(finding.action)
        success = finding.action != CorrectiveAction.REFRESH_STUCK_STAGE
        return CorrectionEvent(
            finding_id=finding.finding_id,
            action=finding.action,
            success=success,
            message="ok" if success else "failed",
            component=finding.component,
        )

    registry.register(CorrectiveAction.REFRESH_STUCK_STAGE, handler)
    registry.register(CorrectiveAction.ESCALATE_ANALYST, handler)

    bus = EventBus()
    controller = SelfHealingController(
        stale_stage_seconds=1.0,
        action_registry=registry,
        event_bus=bus,
    )
    controller.dampening_window.configure_cooldown(
        CorrectiveAction.REFRESH_STUCK_STAGE,
        HealthComponent.PIPELINE_STAGE,
        0.0,
    )
    controller.subscribe_event_bus()

    async def fire() -> None:
        await controller._process_push_metric(
            HealthMetric(
                component=HealthComponent.PIPELINE_STAGE,
                name="stage_age_seconds",
                value=10.0,
                labels={"job_id": "job-1"},
            )
        )

    await fire()
    await fire()
    assert CorrectiveAction.ESCALATE_ANALYST not in seen
    await fire()
    assert CorrectiveAction.ESCALATE_ANALYST in seen

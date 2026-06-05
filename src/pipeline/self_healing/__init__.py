"""Package for the self-healing controller module with event-driven extensions."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.pipeline.self_healing import (
        SelfHealingController,
        CorrectiveActionRegistry,
        CorrectionEvent,
        CorrectiveAction,
        HealthComponent,
        HealthFinding,
        HealthMetric,
        HealthStatus,
        PipelineHealthSnapshot,
    )
    from src.pipeline.self_healing.dampening import DampeningWindow
    from src.pipeline.self_healing.history_store import CorrectionHistoryStore

__all__ = [
    "SelfHealingController",
    "CorrectiveActionRegistry",
    "CorrectionEvent",
    "CorrectiveAction",
    "HealthComponent",
    "HealthFinding",
    "HealthMetric",
    "HealthStatus",
    "PipelineHealthSnapshot",
    "DampeningWindow",
    "CorrectionHistoryStore",
]

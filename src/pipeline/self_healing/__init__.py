"""Package for the self-healing controller module with event-driven extensions."""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.core.contracts.health import (
        CorrectionEvent,
        CorrectiveAction,
        HealthComponent,
        HealthFinding,
        HealthMetric,
        HealthStatus,
        PipelineHealthSnapshot,
    )
    from src.pipeline.self_healing.controller import CorrectiveActionRegistry, SelfHealingController
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


def __getattr__(name: str) -> Any:  # type: ignore[override]
    if name == "SelfHealingController":
        from src.pipeline.self_healing.controller import SelfHealingController

        return SelfHealingController
    if name == "CorrectiveActionRegistry":
        from src.pipeline.self_healing.controller import CorrectiveActionRegistry

        return CorrectiveActionRegistry
    if name == "DampeningWindow":
        from src.pipeline.self_healing.dampening import DampeningWindow

        return DampeningWindow
    if name == "CorrectionHistoryStore":
        from src.pipeline.self_healing.history_store import CorrectionHistoryStore

        return CorrectionHistoryStore
    if name == "CorrectionEvent":
        from src.core.contracts.health import CorrectionEvent

        return CorrectionEvent
    if name == "CorrectiveAction":
        from src.core.contracts.health import CorrectiveAction

        return CorrectiveAction
    if name == "HealthComponent":
        from src.core.contracts.health import HealthComponent

        return HealthComponent
    if name == "HealthFinding":
        from src.core.contracts.health import HealthFinding

        return HealthFinding
    if name == "HealthMetric":
        from src.core.contracts.health import HealthMetric

        return HealthMetric
    if name == "HealthStatus":
        from src.core.contracts.health import HealthStatus

        return HealthStatus
    if name == "PipelineHealthSnapshot":
        from src.core.contracts.health import PipelineHealthSnapshot

        return PipelineHealthSnapshot
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

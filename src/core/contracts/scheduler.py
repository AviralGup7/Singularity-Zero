"""Scheduler and target queue contracts."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SchedulerProtocol(Protocol):
    """Contract for general task and target schedulers."""

    def schedule(self, task: Any) -> Any:
        ...

    def cancel(self, task_id: str) -> bool:
        ...

    def get_stats(self) -> dict[str, Any]:
        ...


@runtime_checkable
class PriorityQueueContract(Protocol):
    """Contract for dynamic target priority queues."""

    def pop(self) -> Any:
        ...

    def peek(self) -> Any:
        ...

    def boost_url(self, url: str, factor: float = 2.0, reason: str = "") -> bool:
        ...

    def boost_from_findings(self, findings: list[dict[str, Any]]) -> list[str]:
        ...

    def should_terminate_early(
        self, threshold_ratio: float = 0.3, min_items: int = 5
    ) -> bool:
        ...

    def get_stats(self) -> dict[str, Any]:
        ...


@runtime_checkable
class AdaptiveCoordinatorContract(Protocol):
    """Contract for adaptive scanning coordinators."""

    @property
    def queue(self) -> Any:
        ...

    async def run(self, save_delta_fn: Any | None = None) -> Any:
        ...


__all__ = [
    "AdaptiveCoordinatorContract",
    "PriorityQueueContract",
    "SchedulerProtocol",
]

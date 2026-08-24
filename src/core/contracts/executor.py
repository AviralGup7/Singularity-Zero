"""Task and probe execution contracts."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ExecutionResultContract(Protocol):
    """Contract for execution results."""

    success: bool
    duration_ms: float
    error: str


@runtime_checkable
class TaskExecutorProtocol(Protocol):
    """Contract for task execution services."""

    def execute_task(
        self,
        task_name: str,
        payload: dict[str, Any],
        timeout_seconds: float = 300.0,
    ) -> dict[str, Any]:
        ...


@runtime_checkable
class ProbeExecutorProtocol(Protocol):
    """Contract for asynchronous probe callable services."""

    async def probe(self, url: str) -> list[dict[str, Any]]:
        ...


__all__ = [
    "ExecutionResultContract",
    "ProbeExecutorProtocol",
    "TaskExecutorProtocol",
]

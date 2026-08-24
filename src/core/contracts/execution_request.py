"""Contracts and protocols for formal ExecutionRequest, Authorization, Scheduling, and Worker handoff."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ExecutionRequestProtocol(Protocol):
    """Protocol representing an immutable contract of intent for execution."""

    request_id: str
    tenant_id: str
    stage: str
    deadline: float

    def to_dict(self) -> dict[str, Any]:
        """Serialize execution request to primitive dictionary."""
        ...


@runtime_checkable
class ExecutionResultProtocol(Protocol):
    """Protocol representing the outcome of an ExecutionRequest."""

    request_id: str
    tenant_id: str
    outcome: str
    duration_seconds: float
    error: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize execution result to primitive dictionary."""
        ...


@runtime_checkable
class ExecutionAuthorizerProtocol(Protocol):
    """Protocol for validating scope and authorization before scheduling."""

    def authorize(self, request: Any) -> Any:
        """Validate scope assertion and emit an authorized execution ticket."""
        ...


@runtime_checkable
class ExecutionSchedulerProtocol(Protocol):
    """Protocol for capacity and priority dispatching of authorized requests."""

    def schedule(self, ticket_or_request: Any) -> bool:
        """Schedule an authorized execution request."""
        ...


@runtime_checkable
class ExecutionWorkerProtocol(Protocol):
    """Protocol for stateless worker execution without decision rediscovery."""

    def execute(self, request: Any) -> Any:
        """Execute the request deterministically and yield ExecutionResult."""
        ...


__all__ = [
    "ExecutionAuthorizerProtocol",
    "ExecutionRequestProtocol",
    "ExecutionResultProtocol",
    "ExecutionSchedulerProtocol",
    "ExecutionWorkerProtocol",
]

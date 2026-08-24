"""Resource guard and budget enforcement contracts."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ResourceGuardContract(Protocol):
    """Contract for memory and OOM guard management."""

    def check_critical_oom(self) -> None:
        ...

    def should_skip_stage(
        self, stage_name: str, target_count: int = 1, url_count: int = 0
    ) -> tuple[bool, str]:
        ...

    def get_concurrency_cap(
        self, stage_name: str, requested_concurrency: int = 10
    ) -> int:
        ...


@runtime_checkable
class BudgetEnforcerContract(Protocol):
    """Contract for hunt resource bounds (time, requests, findings)."""

    def is_exhausted(self) -> bool:
        ...

    def exhausted_axes(self) -> tuple[Any, ...]:
        ...

    def record_request(self, count: int = 1) -> None:
        ...

    def record_finding(self, confidence: float) -> None:
        ...

    def snapshot(self) -> Any:
        ...


__all__ = [
    "BudgetEnforcerContract",
    "ResourceGuardContract",
]

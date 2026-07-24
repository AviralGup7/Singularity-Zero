"""Abstract contract for resource monitoring and RAM availability checking."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ResourceGuardProtocol(Protocol):
    """Protocol defining resource guard capacity checking capabilities."""

    def check_available_ram_for_dispatch(
        self,
        estimated_ram_mb: int,
        in_flight_count: int,
        in_flight_avg_ram_mb: int,
    ) -> tuple[bool, str | None]:
        """Check whether sufficient system RAM is available to dispatch a task."""
        ...

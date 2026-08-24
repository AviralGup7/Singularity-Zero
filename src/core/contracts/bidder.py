"""Bidding and dispatch priority contracts."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class BidContract(Protocol):
    """Structural contract for calculated bids."""

    score: float


@runtime_checkable
class BidWeightsContract(Protocol):
    """Contract for multi-objective dispatch weights."""

    priority: float
    exploitability: float
    business_criticality: float


@runtime_checkable
class BidderProtocol(Protocol):
    """Contract for target and task bidding calculators."""

    def calculate_bid(
        self,
        url: str,
        base_priority: float,
        current_priority: float,
        metadata: dict[str, Any],
    ) -> BidContract:
        ...

    def __call__(
        self,
        url: str,
        base_priority: float,
        current_priority: float,
        metadata: dict[str, Any],
    ) -> BidContract:
        ...


__all__ = [
    "BidContract",
    "BidWeightsContract",
    "BidderProtocol",
]

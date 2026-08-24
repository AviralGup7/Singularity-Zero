"""Immutable Domain Events for Event Sourcing and reactive pipeline telemetry."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Base record for all immutable domain events."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    event_type: str = "domain_event"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True, slots=True)
class TargetEnqueuedEvent(DomainEvent):
    url: str = ""
    priority: float = 0.0
    event_type: str = "target_enqueued"

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({"url": self.url, "priority": self.priority})
        return d


@dataclass(frozen=True, slots=True)
class TargetDispatchedEvent(DomainEvent):
    url: str = ""
    worker_id: str = ""
    event_type: str = "target_dispatched"

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({"url": self.url, "worker_id": self.worker_id})
        return d


@dataclass(frozen=True, slots=True)
class FindingDiscoveredEvent(DomainEvent):
    url: str = ""
    category: str = ""
    severity: str = ""
    confidence: float = 0.0
    title: str = ""
    event_type: str = "finding_discovered"

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "url": self.url,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
        })
        return d


@dataclass(frozen=True, slots=True)
class TargetBoostedEvent(DomainEvent):
    url: str = ""
    old_priority: float = 0.0
    new_priority: float = 0.0
    factor: float = 1.0
    reason: str = ""
    event_type: str = "target_boosted"

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "url": self.url,
            "old_priority": self.old_priority,
            "new_priority": self.new_priority,
            "factor": self.factor,
            "reason": self.reason,
        })
        return d


@dataclass(frozen=True, slots=True)
class BudgetTickEvent(DomainEvent):
    elapsed_seconds: float = 0.0
    requests_count: int = 0
    findings_count: int = 0
    is_exhausted: bool = False
    event_type: str = "budget_tick"

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.update({
            "elapsed_seconds": self.elapsed_seconds,
            "requests_count": self.requests_count,
            "findings_count": self.findings_count,
            "is_exhausted": self.is_exhausted,
        })
        return d


__all__ = [
    "BudgetTickEvent",
    "DomainEvent",
    "FindingDiscoveredEvent",
    "TargetBoostedEvent",
    "TargetDispatchedEvent",
    "TargetEnqueuedEvent",
]

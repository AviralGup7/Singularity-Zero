"""Real-Time Linear Temporal Logic (LTL) Formal Safety & Liveness Verifier.

Monitors pipeline event traces and verifies mathematical safety invariants
(e.g., Target Never Dispatched Out-of-Scope) and liveness invariants.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from src.core.events.events import DomainEvent


class LTLViolationError(Exception):
    """Raised when a formal Linear Temporal Logic safety invariant is breached."""


@dataclass(frozen=True, slots=True)
class SafetyInvariant:
    """Represents an invariant that must ALWAYS hold: □ (Predicate)."""

    name: str
    predicate: Callable[[DomainEvent], bool]
    failure_message: str


class LTLRuntimeVerifier:
    """Online formal model checker verifying LTL properties over event streams."""

    def __init__(self) -> None:
        self._safety_invariants: list[SafetyInvariant] = []
        self._event_history: list[DomainEvent] = []

    def add_safety_invariant(
        self,
        name: str,
        predicate: Callable[[DomainEvent], bool],
        failure_message: str = "Safety invariant violated",
    ) -> None:
        self._safety_invariants.append(SafetyInvariant(name, predicate, failure_message))

    def verify_event(self, event: DomainEvent) -> None:
        """Verify all safety invariants against the current event."""
        self._event_history.append(event)
        for inv in self._safety_invariants:
            if not inv.predicate(event):
                raise LTLViolationError(
                    f"Formal LTL Safety Invariant '{inv.name}' VIOLATED by event {event.event_type} "
                    f"(ID: {event.event_id}): {inv.failure_message}"
                )

    def verify_liveness_eventually(
        self,
        trigger_predicate: Callable[[DomainEvent], bool],
        fulfill_predicate: Callable[[DomainEvent], bool],
    ) -> bool:
        """Verify liveness property: Trigger => ◊ Fulfill."""
        triggered = any(trigger_predicate(e) for e in self._event_history)
        if not triggered:
            return True
        return any(fulfill_predicate(e) for e in self._event_history)


__all__ = [
    "LTLRuntimeVerifier",
    "LTLViolationError",
    "SafetyInvariant",
]

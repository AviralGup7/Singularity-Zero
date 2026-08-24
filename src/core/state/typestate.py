"""Formal Finite State Machine (FSM) typestate invariants for scan targets and findings."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class InvalidStateTransitionError(Exception):
    """Raised when an illegal lifecycle state transition is attempted."""


class TargetState(StrEnum):
    """Closed lifecycle states for a scan target."""

    ENQUEUED = "enqueued"
    LEASED = "leased"
    PROBING = "probing"
    EVALUATING = "evaluating"
    COMPLETED = "completed"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


# Valid state transitions graph for ScanTarget
_VALID_TARGET_TRANSITIONS: dict[TargetState, frozenset[TargetState]] = {
    TargetState.ENQUEUED: frozenset({TargetState.LEASED, TargetState.SUPPRESSED}),
    TargetState.LEASED: frozenset({TargetState.PROBING, TargetState.ENQUEUED, TargetState.FAILED}),
    TargetState.PROBING: frozenset({TargetState.EVALUATING, TargetState.FAILED}),
    TargetState.EVALUATING: frozenset({TargetState.COMPLETED, TargetState.FAILED, TargetState.SUPPRESSED}),
    TargetState.COMPLETED: frozenset(),  # Terminal
    TargetState.FAILED: frozenset({TargetState.ENQUEUED}),  # Retry
    TargetState.SUPPRESSED: frozenset(),  # Terminal
}


@dataclass(frozen=True, slots=True)
class TargetTypestate:
    """Immutable typestate container enforcing mathematical FSM invariants."""

    url: str
    state: TargetState = TargetState.ENQUEUED
    history: tuple[tuple[str, float], ...] = field(default_factory=lambda: (("enqueued", time.time()),))
    reason: str = ""

    def transition_to(self, next_state: TargetState, reason: str = "") -> TargetTypestate:
        """Transition target to next_state, verifying FSM legality."""
        allowed = _VALID_TARGET_TRANSITIONS.get(self.state, frozenset())
        if next_state not in allowed:
            raise InvalidStateTransitionError(
                f"Illegal TargetState transition from '{self.state}' to '{next_state}' for {self.url}. "
                f"Allowed: {sorted(s.value for s in allowed)}"
            )
        now = time.time()
        new_history = self.history + ((next_state.value, now),)
        return TargetTypestate(
            url=self.url,
            state=next_state,
            history=new_history,
            reason=reason,
        )

    def is_terminal(self) -> bool:
        return len(_VALID_TARGET_TRANSITIONS.get(self.state, frozenset())) == 0


class FindingState(StrEnum):
    """Closed lifecycle states for a security finding."""

    DISCOVERED = "discovered"
    VERIFYING = "verifying"
    CONFIRMED = "confirmed"
    SUPPRESSED = "suppressed"
    DROPPED = "dropped"


_VALID_FINDING_TRANSITIONS: dict[FindingState, frozenset[FindingState]] = {
    FindingState.DISCOVERED: frozenset({FindingState.VERIFYING, FindingState.DROPPED}),
    FindingState.VERIFYING: frozenset({FindingState.CONFIRMED, FindingState.SUPPRESSED, FindingState.DROPPED}),
    FindingState.CONFIRMED: frozenset({FindingState.SUPPRESSED}),
    FindingState.SUPPRESSED: frozenset({FindingState.CONFIRMED}),
    FindingState.DROPPED: frozenset(),  # Terminal
}


@dataclass(frozen=True, slots=True)
class FindingTypestate:
    """Immutable typestate container for security finding lifecycle."""

    finding_id: str
    state: FindingState = FindingState.DISCOVERED
    history: tuple[tuple[str, float], ...] = field(default_factory=lambda: (("discovered", time.time()),))
    reason: str = ""

    def transition_to(self, next_state: FindingState, reason: str = "") -> FindingTypestate:
        """Transition finding to next_state, verifying FSM legality."""
        allowed = _VALID_FINDING_TRANSITIONS.get(self.state, frozenset())
        if next_state not in allowed:
            raise InvalidStateTransitionError(
                f"Illegal FindingState transition from '{self.state}' to '{next_state}' for {self.finding_id}. "
                f"Allowed: {sorted(s.value for s in allowed)}"
            )
        now = time.time()
        new_history = self.history + ((next_state.value, now),)
        return FindingTypestate(
            finding_id=self.finding_id,
            state=next_state,
            history=new_history,
            reason=reason,
        )


__all__ = [
    "FindingState",
    "FindingTypestate",
    "InvalidStateTransitionError",
    "TargetState",
    "TargetTypestate",
]

"""Command-Sourcing Envelopes, Authoritative Event Envelopes, and Schema Upcasters.

Implements the formal command/event contract for the state-machine-driven architecture:
- Explicit Command Envelopes (ReserveBudget, GrantLease, SubmitClaim, SettleExecution, ExpireLease)
- Strongly-typed Event Envelopes with monotonic log offsets, aggregate versions, and causation IDs
- Schema Upcaster Registry to ensure backward-compatible deterministic replay
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class CommandEnvelope:
    """Immutable command envelope submitted to the authoritative control plane."""

    command_id: str
    command_type: str
    aggregate_id: str
    payload: Mapping[str, Any]
    correlation_id: str
    causation_id: str
    created_at_unix: float = field(default_factory=time.time)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "command_type": self.command_type,
            "aggregate_id": self.aggregate_id,
            "payload": dict(self.payload),
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "created_at_unix": self.created_at_unix,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandEnvelope:
        return cls(
            command_id=str(data.get("command_id", uuid.uuid4().hex)),
            command_type=str(data.get("command_type", "")),
            aggregate_id=str(data.get("aggregate_id", "")),
            payload=dict(data.get("payload", {})),
            correlation_id=str(data.get("correlation_id", "")),
            causation_id=str(data.get("causation_id", "")),
            created_at_unix=float(data.get("created_at_unix", time.time())),
            schema_version=int(data.get("schema_version", 1)),
        )


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    """Immutable event record committed to the durable log."""

    event_id: str
    event_type: str
    aggregate_id: str
    aggregate_version: int
    payload: Mapping[str, Any]
    correlation_id: str
    causation_id: str
    log_offset: int = 0
    committed_at_unix: float = field(default_factory=time.time)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "aggregate_id": self.aggregate_id,
            "aggregate_version": self.aggregate_version,
            "payload": dict(self.payload),
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "log_offset": self.log_offset,
            "committed_at_unix": self.committed_at_unix,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EventEnvelope:
        return cls(
            event_id=str(data.get("event_id", uuid.uuid4().hex)),
            event_type=str(data.get("event_type", "")),
            aggregate_id=str(data.get("aggregate_id", "")),
            aggregate_version=int(data.get("aggregate_version", 1)),
            payload=dict(data.get("payload", {})),
            correlation_id=str(data.get("correlation_id", "")),
            causation_id=str(data.get("causation_id", "")),
            log_offset=int(data.get("log_offset", 0)),
            committed_at_unix=float(data.get("committed_at_unix", time.time())),
            schema_version=int(data.get("schema_version", 1)),
        )


UpcasterFn = Callable[[dict[str, Any]], dict[str, Any]]


class SchemaUpcasterRegistry:
    """Registry of event schema upcasters ensuring deterministic replay across versions."""

    def __init__(self) -> None:
        # Key: (event_type, from_version) -> (to_version, UpcasterFn)
        self._upcasters: dict[tuple[str, int], tuple[int, UpcasterFn]] = {}

    def register(
        self,
        event_type: str,
        from_version: int,
        to_version: int,
        fn: UpcasterFn,
    ) -> None:
        self._upcasters[(event_type, from_version)] = (to_version, fn)

    def upcast(self, event_dict: dict[str, Any], target_version: int | None = None) -> dict[str, Any]:
        """Progressively upcast an event dictionary until the target version is reached."""
        current = dict(event_dict)
        event_type = current.get("event_type", "")
        current_ver = int(current.get("schema_version", 1))

        while True:
            key = (event_type, current_ver)
            if key not in self._upcasters:
                break
            next_ver, fn = self._upcasters[key]
            if target_version is not None and current_ver >= target_version:
                break
            payload = fn(dict(current.get("payload", {})))
            current["payload"] = payload
            current["schema_version"] = next_ver
            current_ver = next_ver

        return current


GLOBAL_UPCASTER_REGISTRY = SchemaUpcasterRegistry()

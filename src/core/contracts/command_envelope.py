"""Command-Sourcing Envelopes, Authoritative Event Envelopes, and Schema Upcasters.

Implements the formal command/event contract for the state-machine-driven architecture:
- Explicit Command Envelopes with expected aggregate version and globally unique IDs
- Deterministic Committed Entries encapsulating command, transition result, and emitted events
- Strongly-typed Event Envelopes with deterministic event IDs: SHA256(partition || index || seq)
- Certified Command Receipts with state hash bindings and leader cryptographic signatures
- Schema Upcaster Registry to ensure backward-compatible deterministic replay
"""

from __future__ import annotations

import hashlib
import json
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
    expected_aggregate_version: int | None = None
    traceparent: str = ""
    tracestate: str = ""
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
            "expected_aggregate_version": self.expected_aggregate_version,
            "traceparent": self.traceparent,
            "tracestate": self.tracestate,
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
            expected_aggregate_version=(
                int(data["expected_aggregate_version"])
                if data.get("expected_aggregate_version") is not None
                else None
            ),
            traceparent=str(data.get("traceparent", "")),
            tracestate=str(data.get("tracestate", "")),
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
    partition_id: str = "P-0000"
    raft_term: int = 1
    raft_index: int = 0
    log_offset: int = 0
    traceparent: str = ""
    tracestate: str = ""
    committed_at_unix: float = field(default_factory=time.time)
    schema_version: int = 1

    @staticmethod
    def derive_event_id(partition_id: str, raft_index: int, event_sequence: int = 0) -> str:
        """Derive deterministic event ID from partition coordinate: SHA256(partition || index || seq)."""
        raw = f"{partition_id}:{raft_index}:{event_sequence}".encode("utf-8")
        return f"evt-{hashlib.sha256(raw).hexdigest()[:16]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "aggregate_id": self.aggregate_id,
            "aggregate_version": self.aggregate_version,
            "payload": dict(self.payload),
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "partition_id": self.partition_id,
            "raft_term": self.raft_term,
            "raft_index": self.raft_index,
            "log_offset": self.log_offset,
            "traceparent": self.traceparent,
            "tracestate": self.tracestate,
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
            partition_id=str(data.get("partition_id", "P-0000")),
            raft_term=int(data.get("raft_term", 1)),
            raft_index=int(data.get("raft_index", data.get("log_offset", 0))),
            log_offset=int(data.get("log_offset", 0)),
            traceparent=str(data.get("traceparent", "")),
            tracestate=str(data.get("tracestate", "")),
            committed_at_unix=float(data.get("committed_at_unix", time.time())),
            schema_version=int(data.get("schema_version", 1)),
        )


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Deterministic outcome of applying a command inside Level 1 FSM."""

    status: str  # "SUCCESS", "REJECTED", "NO_OP", "DUPLICATE"
    aggregate_id: str
    resulting_aggregate_version: int
    result_code: str
    result_payload: Mapping[str, Any] = field(default_factory=dict)
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "aggregate_id": self.aggregate_id,
            "resulting_aggregate_version": self.resulting_aggregate_version,
            "result_code": self.result_code,
            "result_payload": dict(self.result_payload),
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandResult:
        return cls(
            status=str(data.get("status", "SUCCESS")),
            aggregate_id=str(data.get("aggregate_id", "")),
            resulting_aggregate_version=int(data.get("resulting_aggregate_version", 0)),
            result_code=str(data.get("result_code", "")),
            result_payload=dict(data.get("result_payload", {})),
            error_message=str(data.get("error_message", "")),
        )


@dataclass(frozen=True, slots=True)
class CommittedEntry:
    """Model B Committed Entry carrying command, deterministic result, and emitted events."""

    partition_id: str
    raft_term: int
    raft_index: int
    entry_hash: str
    previous_entry_hash: str
    command: CommandEnvelope
    transition_result: CommandResult
    emitted_events: tuple[EventEnvelope, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "raft_term": self.raft_term,
            "raft_index": self.raft_index,
            "entry_hash": self.entry_hash,
            "previous_entry_hash": self.previous_entry_hash,
            "command": self.command.to_dict(),
            "transition_result": self.transition_result.to_dict(),
            "emitted_events": [e.to_dict() for e in self.emitted_events],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommittedEntry:
        events = tuple(
            EventEnvelope.from_dict(e) for e in data.get("emitted_events", [])
        )
        return cls(
            partition_id=str(data.get("partition_id", "P-0000")),
            raft_term=int(data.get("raft_term", 1)),
            raft_index=int(data.get("raft_index", 0)),
            entry_hash=str(data.get("entry_hash", "")),
            previous_entry_hash=str(data.get("previous_entry_hash", "")),
            command=CommandEnvelope.from_dict(data["command"]),
            transition_result=CommandResult.from_dict(data["transition_result"]),
            emitted_events=events,
        )


@dataclass(frozen=True, slots=True)
class CommandReceipt:
    """Cryptographically signed receipt of state transition constructed by the active Raft leader."""

    receipt_id: str
    command_id: str
    partition_id: str
    raft_term: int
    raft_index: int
    entry_hash: str
    aggregate_id: str
    resulting_aggregate_version: int
    result_code: str
    result_payload_hash: str
    emitted_event_ids: tuple[str, ...]
    previous_state_hash: str
    state_hash_at_commit: str
    signer_key_id: str
    cryptographic_signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "command_id": self.command_id,
            "partition_id": self.partition_id,
            "raft_term": self.raft_term,
            "raft_index": self.raft_index,
            "entry_hash": self.entry_hash,
            "aggregate_id": self.aggregate_id,
            "resulting_aggregate_version": self.resulting_aggregate_version,
            "result_code": self.result_code,
            "result_payload_hash": self.result_payload_hash,
            "emitted_event_ids": list(self.emitted_event_ids),
            "previous_state_hash": self.previous_state_hash,
            "state_hash_at_commit": self.state_hash_at_commit,
            "signer_key_id": self.signer_key_id,
            "cryptographic_signature": self.cryptographic_signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CommandReceipt:
        return cls(
            receipt_id=str(data.get("receipt_id", "")),
            command_id=str(data.get("command_id", "")),
            partition_id=str(data.get("partition_id", "P-0000")),
            raft_term=int(data.get("raft_term", 1)),
            raft_index=int(data.get("raft_index", 0)),
            entry_hash=str(data.get("entry_hash", "")),
            aggregate_id=str(data.get("aggregate_id", "")),
            resulting_aggregate_version=int(data.get("resulting_aggregate_version", 0)),
            result_code=str(data.get("result_code", "")),
            result_payload_hash=str(data.get("result_payload_hash", "")),
            emitted_event_ids=tuple(str(e) for e in data.get("emitted_event_ids", ())),
            previous_state_hash=str(data.get("previous_state_hash", "")),
            state_hash_at_commit=str(data.get("state_hash_at_commit", "")),
            signer_key_id=str(data.get("signer_key_id", "")),
            cryptographic_signature=str(data.get("cryptographic_signature", "")),
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

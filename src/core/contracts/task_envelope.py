from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

TASK_ENVELOPE_VERSION = "v1"


@dataclass(frozen=True, slots=True)
class TaskRetryPolicy:
    """Portable retry policy included with distributed task envelopes."""

    max_attempts: int = 3
    initial_backoff_seconds: float = 1.0
    backoff_multiplier: float = 2.0
    max_backoff_seconds: float = 60.0
    jitter: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_attempts": int(max(0, self.max_attempts)),
            "initial_backoff_seconds": float(max(0.0, self.initial_backoff_seconds)),
            "backoff_multiplier": float(max(1.0, self.backoff_multiplier)),
            "max_backoff_seconds": float(max(0.0, self.max_backoff_seconds)),
            "jitter": bool(self.jitter),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> TaskRetryPolicy:
        data = payload or {}
        return cls(
            max_attempts=int(data.get("max_attempts", 3) or 3),
            initial_backoff_seconds=float(data.get("initial_backoff_seconds", 1.0) or 1.0),
            backoff_multiplier=float(data.get("backoff_multiplier", 2.0) or 2.0),
            max_backoff_seconds=float(data.get("max_backoff_seconds", 60.0) or 60.0),
            jitter=bool(data.get("jitter", True)),
        )


@dataclass(frozen=True, slots=True)
class TaskEnvelope:
    """Canonical queued/distributed task contract.

    This envelope decouples producers and workers from in-process orchestrator
    internals by standardizing task payload shape and retry metadata.
    """

    type: str
    payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    retry_policy: TaskRetryPolicy = field(default_factory=TaskRetryPolicy)
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    schema_version: str = TASK_ENVELOPE_VERSION
    traceparent: str = field(default_factory=lambda: f"00-{uuid.uuid4().hex[:32]}-{'0' * 16}-01")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "type": self.type,
            "payload": dict(self.payload),
            "metadata": dict(self.metadata),
            "retry_policy": self.retry_policy.to_dict(),
            "correlation_id": self.correlation_id,
            "traceparent": self.traceparent,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> TaskEnvelope:
        schema_version = str(
            payload.get("schema_version", TASK_ENVELOPE_VERSION) or TASK_ENVELOPE_VERSION
        )
        if schema_version != TASK_ENVELOPE_VERSION:
            raise ValueError(
                f"Unsupported task envelope schema_version '{schema_version}', expected '{TASK_ENVELOPE_VERSION}'"
            )
        return cls(
            schema_version=schema_version,
            type=str(payload.get("type", "") or ""),
            payload=dict(payload.get("payload", {}) or {}),
            metadata=dict(payload.get("metadata", {}) or {}),
            retry_policy=TaskRetryPolicy.from_dict(payload.get("retry_policy", {})),
            correlation_id=str(payload.get("correlation_id", uuid.uuid4().hex) or uuid.uuid4().hex),
            traceparent=str(
                payload.get("traceparent", f"00-{uuid.uuid4().hex[:32]}-{'0' * 16}-01")
            ),
        )

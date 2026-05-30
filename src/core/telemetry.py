"""Structured pipeline telemetry events for dashboard replay and inspection."""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

TELEMETRY_SCHEMA_VERSION = "telemetry.v2"


@dataclass(frozen=True)
class TelemetryEvent:
    """Replayable event emitted by a pipeline stage, sub-stage, or check."""

    event_id: str
    schema_version: str
    event_type: str
    timestamp: str
    epoch: float
    stage: str
    status: str
    message: str
    source: str
    trace_id: str
    parent_id: str = ""
    check_id: str = ""
    artifact_type: str = ""
    artifact_id: str = ""
    finding_id: str = ""
    severity: str = ""
    target: str = ""
    run_id: str = ""
    sequence: int = 0
    metrics: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "schema_version": self.schema_version,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "epoch": self.epoch,
            "stage": self.stage,
            "status": self.status,
            "message": self.message,
            "source": self.source,
            "trace_id": self.trace_id,
            "parent_id": self.parent_id,
            "check_id": self.check_id,
            "artifact_type": self.artifact_type,
            "artifact_id": self.artifact_id,
            "finding_id": self.finding_id,
            "severity": self.severity,
            "target": self.target,
            "run_id": self.run_id,
            "sequence": self.sequence,
            "metrics": self.metrics,
            "payload": self.payload,
        }


def stable_event_id(*parts: object) -> str:
    digest = hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"evt_{digest[:24]}"


def build_telemetry_event(
    *,
    event_type: str,
    stage: str,
    message: str = "",
    status: str = "running",
    source: str = "",
    trace_id: str = "",
    parent_id: str = "",
    check_id: str = "",
    artifact_type: str = "",
    artifact_id: str = "",
    finding_id: str = "",
    severity: str = "",
    target: str = "",
    run_id: str = "",
    sequence: int = 0,
    metrics: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    event_id: str = "",
    epoch: float | None = None,
) -> dict[str, Any]:
    ts_epoch = time.time() if epoch is None else epoch
    resolved_trace = trace_id or run_id or str(uuid.uuid4())
    resolved_id = event_id or stable_event_id(
        TELEMETRY_SCHEMA_VERSION,
        resolved_trace,
        stage,
        event_type,
        check_id,
        artifact_type,
        artifact_id,
        finding_id,
        sequence,
        message,
    )
    return TelemetryEvent(
        event_id=resolved_id,
        schema_version=TELEMETRY_SCHEMA_VERSION,
        event_type=event_type,
        timestamp=datetime.fromtimestamp(ts_epoch, tz=UTC).isoformat(),
        epoch=round(ts_epoch, 6),
        stage=stage,
        status=status,
        message=message,
        source=source or f"stage.{stage}",
        trace_id=resolved_trace,
        parent_id=parent_id,
        check_id=check_id,
        artifact_type=artifact_type,
        artifact_id=artifact_id,
        finding_id=finding_id,
        severity=severity,
        target=target,
        run_id=run_id,
        sequence=sequence,
        metrics=metrics or {},
        payload=payload or {},
    ).to_dict()


def normalize_telemetry_event(raw: dict[str, Any], *, fallback_stage: str = "") -> dict[str, Any]:
    """Return a complete telemetry event dict from partial legacy payloads."""

    if raw.get("schema_version") == TELEMETRY_SCHEMA_VERSION and raw.get("event_id"):
        return dict(raw)

    stage = str(raw.get("stage") or fallback_stage or "unknown")
    return build_telemetry_event(
        event_type=str(raw.get("event_type") or raw.get("kind") or "stage.progress"),
        stage=stage,
        message=str(raw.get("message") or ""),
        status=str(raw.get("status") or "running"),
        source=str(raw.get("source") or f"stage.{stage}"),
        trace_id=str(raw.get("trace_id") or raw.get("run_id") or ""),
        parent_id=str(raw.get("parent_id") or ""),
        check_id=str(raw.get("check_id") or ""),
        artifact_type=str(raw.get("artifact_type") or ""),
        artifact_id=str(raw.get("artifact_id") or ""),
        finding_id=str(raw.get("finding_id") or ""),
        severity=str(raw.get("severity") or ""),
        target=str(raw.get("target") or raw.get("target_name") or ""),
        run_id=str(raw.get("run_id") or ""),
        sequence=int(raw.get("sequence", 0) or 0),
        metrics=dict(raw.get("metrics") or {}),
        payload=dict(raw.get("payload") or {}),
        event_id=str(raw.get("event_id") or ""),
        epoch=float(raw.get("epoch") or time.time()),
    )

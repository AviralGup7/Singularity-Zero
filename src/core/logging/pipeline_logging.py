"""Pipeline logging utilities for structured progress events and status messages.

Provides emit_* functions for progress tracking, info, warnings, errors,
and retry notifications. All output goes to stdout/stderr with structured
JSON formatting for progress events.
"""

import json
import sys
import types
from typing import Any

from src.core.contracts.pipeline import LOGGING_FORMAT

PROGRESS_PREFIX = str(LOGGING_FORMAT["progress_prefix"])


def emit_progress_event(stage: str, message: str, percent: int, **fields: object) -> None:
    """Publish a STAGE_PROGRESS event to the central event bus.

    Args:
        stage: Current pipeline stage name.
        message: Human-readable progress message.
        percent: Progress percentage (0-100).
        **fields: Additional key-value pairs to include in the event.
    """
    from src.core.events import EventType, get_event_bus
    from src.core.telemetry import build_telemetry_event

    status = str(fields.get("stage_status") or fields.get("status") or "running")
    event_type = str(fields.get("telemetry_event_type") or "stage.progress")
    trace_id = str(fields.get("trace_id") or fields.get("run_id") or "")
    telemetry_event = build_telemetry_event(
        event_type=event_type,
        stage=stage,
        message=message,
        status=status,
        source=f"stage.{stage}",
        trace_id=trace_id,
        check_id=str(fields.get("check_id") or fields.get("sub_stage") or ""),
        artifact_type=str(fields.get("artifact_type") or ""),
        artifact_id=str(fields.get("artifact_id") or ""),
        finding_id=str(fields.get("finding_id") or ""),
        severity=str(fields.get("severity") or ""),
        target=str(fields.get("target") or fields.get("target_name") or ""),
        run_id=str(fields.get("run_id") or ""),
        metrics={
            key: value
            for key, value in fields.items()
            if key
            in {
                "processed",
                "total",
                "stage_percent",
                "targets_done",
                "targets_queued",
                "targets_scanning",
                "requests_per_second",
                "throughput_per_second",
                "confidence_score",
                "vulnerability_likelihood_score",
            }
        },
        payload={"percent": int(percent)},
    )
    payload = {
        "stage": stage,
        "message": message,
        "percent": int(percent),
        "telemetry_schema_version": telemetry_event["schema_version"],
        "telemetry_event": telemetry_event,
    }
    for key, value in fields.items():
        if value is None:
            continue
        payload[str(key)] = value

    # Phase 4: Event Subscribers (#4)
    get_event_bus().emit(
        EventType.STAGE_PROGRESS,
        source=f"stage.{stage}",
        data=payload,
    )


def _json_default(obj: Any) -> Any:
    """Custom JSON encoder for types that are not natively serializable."""
    if isinstance(obj, types.MappingProxyType):
        return dict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def emit_info(message: str) -> None:
    """Emit an informational message to stdout.

    Args:
        message: Message text to display.
    """
    sys.stdout.write(f"{message}\n")
    sys.stdout.flush()


def emit_summary(payload: dict[str, Any]) -> None:
    """Emit a formatted JSON summary to stdout.

    Args:
        payload: Dictionary to format as indented JSON.
    """
    emit_info(json.dumps(payload, indent=2, default=_json_default))



def emit_warning(message: str) -> None:
    """Emit a warning message to stderr.

    Args:
        message: Warning text to display.
    """
    sys.stderr.write(f"{LOGGING_FORMAT['warning_prefix']}{message}\n")
    sys.stderr.flush()


def emit_error(message: str, *parts: object) -> None:
    """Emit an error message to stderr.

    Args:
        message: Error text to display.
    """
    if parts:
        message = " ".join([str(message), *(str(part) for part in parts)])
    sys.stderr.write(f"{LOGGING_FORMAT['error_prefix']}{message}\n")
    sys.stderr.flush()


def emit_retry_warning(
    target: str,
    *,
    reason: str,
    attempt: int,
    max_attempts: int,
    delay: float,
) -> None:
    """Emit a structured retry warning to stderr.

    Args:
        target: The resource or command being retried.
        reason: Why the retry is happening.
        attempt: Current attempt number (1-based).
        max_attempts: Total maximum attempts allowed.
        delay: Seconds to wait before the next attempt.
    """
    msg = (
        f"Retrying {target} (attempt {attempt}/{max_attempts}) "
        f"after {delay:.2f}s — reason: {reason}"
    )
    sys.stderr.write(f"{LOGGING_FORMAT['warning_prefix']}{msg}\n")
    sys.stderr.flush()


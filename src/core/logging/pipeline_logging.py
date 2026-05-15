"""Pipeline logging utilities for structured progress events and status messages.

Provides emit_* functions for progress tracking, info, warnings, errors,
and retry notifications. All output goes to stdout/stderr with structured
JSON formatting for progress events.
"""

import json
import sys
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

    payload = {"stage": stage, "message": message, "percent": int(percent)}
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


def emit_info(message: str) -> None:
    """Emit an informational message to stdout.

    Args:
        message: Message text to display.
    """
    print(message, flush=True)


def emit_summary(payload: dict[str, Any]) -> None:
    """Emit a formatted JSON summary to stdout.

    Args:
        payload: Dictionary to format as indented JSON.
    """
    emit_info(json.dumps(payload, indent=2))


def emit_warning(message: str) -> None:
    """Emit a warning message to stderr.

    Args:
        message: Warning text to display.
    """
    print(f"{LOGGING_FORMAT['warning_prefix']}{message}", file=sys.stderr, flush=True)


def emit_retry_warning(
    subject: str, *, reason: str, attempt: int, max_attempts: int, delay: float
) -> None:
    """Emit a retry warning with attempt count and delay information.

    Args:
        subject: What is being retried (e.g., tool name).
        reason: Why the retry is needed.
        attempt: Current attempt number (0-based).
        max_attempts: Maximum number of attempts.
        delay: Delay in seconds before the retry.
    """
    emit_warning(
        f"{subject} {reason}; retrying attempt {attempt + 1}/{max_attempts} in {delay:.1f}s"
    )


def emit_error(message: str) -> None:
    """Emit an error message to stderr.

    Args:
        message: Error text to display.
    """
    print(f"{LOGGING_FORMAT['error_prefix']}{message}", file=sys.stderr, flush=True)

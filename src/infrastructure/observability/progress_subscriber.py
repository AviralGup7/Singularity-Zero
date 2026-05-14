"""Event subscriber for terminal progress reporting.

Decouples the terminal UI (stdout) from the pipeline domain logic by
listening to STAGE_PROGRESS events.
"""

from __future__ import annotations

import json

from src.core.contracts.pipeline import LOGGING_FORMAT
from src.core.events import EventBus, EventType, PipelineEvent

PROGRESS_PREFIX = str(LOGGING_FORMAT["progress_prefix"])


class ProgressSubscriber:
    """Subscriber that prints progress events to stdout in structured JSON."""

    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus
        self._subscription_id: str | None = None

    def start(self) -> None:
        """Start listening for progress events."""
        if self._subscription_id:
            return
        self._subscription_id = self._event_bus.subscribe(
            EventType.STAGE_PROGRESS, self._on_progress
        )

    def stop(self) -> None:
        """Stop listening for progress events."""
        if self._subscription_id:
            self._event_bus.unsubscribe(self._subscription_id)
            self._subscription_id = None

    def _on_progress(self, event: PipelineEvent) -> None:
        """Format and print the progress event to stdout."""
        # The 'data' field of the event contains the progress payload.
        # We strip the 'event_schema_version' which is added by event_bus.emit()
        payload = dict(event.data)
        payload.pop("event_schema_version", None)

        print(
            PROGRESS_PREFIX + json.dumps(payload, ensure_ascii=True),
            flush=True,
        )


def register_progress_subscriber(event_bus: EventBus) -> ProgressSubscriber:
    """Helper to create and start a progress subscriber."""
    subscriber = ProgressSubscriber(event_bus)
    subscriber.start()
    return subscriber

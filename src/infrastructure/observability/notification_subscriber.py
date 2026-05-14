"""Event subscriber for pipeline notifications.

Integrates the pipeline event bus with the NotificationManager to send
real-time alerts to Slack, Email, Webhooks, etc.
"""

from __future__ import annotations

import logging

from src.core.events import EventBus, EventType, PipelineEvent
from src.infrastructure.notifications import (
    NotificationManager,
)

logger = logging.getLogger(__name__)


class NotificationSubscriber:
    """Subscriber that sends notifications based on pipeline events."""

    def __init__(self, event_bus: EventBus, manager: NotificationManager) -> None:
        self._event_bus = event_bus
        self._manager = manager
        self._subscription_ids: list[str] = []

    def start(self) -> None:
        """Start listening for events to notify."""
        if self._subscription_ids:
            return

        # Use subscribe_async for handlers that call the async NotificationManager
        mappings = [
            EventType.PIPELINE_STARTED,
            EventType.FINDING_CREATED,
            EventType.PIPELINE_COMPLETE,
            EventType.PIPELINE_ERROR,
        ]

        for event_type in mappings:
            sub_id = self._event_bus.subscribe_async(event_type, self._handle_event)
            self._subscription_ids.append(sub_id)

    def stop(self) -> None:
        """Stop listening for events."""
        for sub_id in self._subscription_ids:
            self._event_bus.unsubscribe(sub_id)
        self._subscription_ids.clear()

    async def _handle_event(self, event: PipelineEvent) -> None:
        """Route pipeline events to appropriate notification manager calls."""
        try:
            if event.event_type == EventType.PIPELINE_STARTED:
                await self._manager.send_scan_status(
                    status="started",
                    target=event.data.get("target", "Unknown"),
                    details={
                        "run_id": event.data.get("run_id"),
                        "mode": event.data.get("mode"),
                    },
                    correlation_id=event.correlation_id,
                )

            elif event.event_type == EventType.PIPELINE_COMPLETE:
                await self._manager.send_scan_status(
                    status="completed",
                    target=event.data.get("target", "Unknown"),
                    details={
                        "run_id": event.data.get("run_id"),
                        "total_findings": event.data.get("total_findings"),
                    },
                    correlation_id=event.correlation_id,
                )

            elif event.event_type == EventType.PIPELINE_ERROR:
                await self._manager.send_scan_status(
                    status="failed",
                    target=event.data.get("target", "Unknown"),
                    details={
                        "run_id": event.data.get("run_id"),
                        "reason": event.data.get("reason"),
                    },
                    correlation_id=event.correlation_id,
                )

            elif event.event_type == EventType.FINDING_CREATED:
                severity = event.data.get("severity", "info").lower()
                # Only notify for medium and above by default to avoid noise
                if severity in ("medium", "high", "critical"):
                    await self._manager.send_finding(
                        finding_title=event.data.get("category", "Vulnerability Detected"),
                        finding_description=f"New {severity} finding discovered at {event.data.get('url')}",
                        severity=severity,
                        target=event.data.get("target"),
                        endpoint=event.data.get("url"),
                        correlation_id=event.correlation_id,
                    )

        except Exception:
            logger.exception("Failed to send notification for event %s", event.event_type.value)


def register_notification_subscriber(
    event_bus: EventBus, manager: NotificationManager
) -> NotificationSubscriber:
    """Helper to create and start a notification subscriber."""
    subscriber = NotificationSubscriber(event_bus, manager)
    subscriber.start()
    return subscriber

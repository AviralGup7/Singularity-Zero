"""In-app notification notifier that bridges NotificationManager to SSE + DB.

This notifier is registered as a channel in NotificationManager so that
every notification sent through the manager is also:
  1. Persisted to SQLite for REST API consumption
  2. Broadcast to connected SSE clients for real-time UI updates
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.infrastructure.notifications.base import (
    BaseNotifier,
    NotificationConfig,
    NotificationEvent,
    NotificationPayload,
    NotificationPriority,
    NotificationResult,
)

logger = logging.getLogger(__name__)

# Severity mapping for the frontend
_PRIORITY_SEVERITY_MAP: dict[NotificationPriority, str] = {
    NotificationPriority.LOW: "low",
    NotificationPriority.MEDIUM: "medium",
    NotificationPriority.HIGH: "high",
    NotificationPriority.CRITICAL: "critical",
}

_EVENT_TYPE_MAP: dict[NotificationEvent, str] = {
    NotificationEvent.SCAN_STARTED: "scan_started",
    NotificationEvent.SCAN_COMPLETED: "scan_completed",
    NotificationEvent.SCAN_FAILED: "scan_failed",
    NotificationEvent.FINDING_DETECTED: "new_finding",
    NotificationEvent.CRITICAL_VULNERABILITY: "new_finding",
    NotificationEvent.RATE_LIMIT_EXCEEDED: "rate_limit_exceeded",
    NotificationEvent.SYSTEM_ERROR: "error",
    NotificationEvent.PIPELINE_TIMEOUT: "pipeline_timeout",
    NotificationEvent.SELF_HEALING_ACTION: "self_healing_action",
    NotificationEvent.COMPLIANCE_VIOLATION: "compliance_violation",
    NotificationEvent.CUSTOM: "custom",
}


class InAppNotifier(BaseNotifier):
    """Notifier that persists to DB and broadcasts via SSE to the frontend.

    Unlike other notifiers, this one is always enabled and has no external
    transport — it feeds the in-app notification center.
    """

    def __init__(
        self,
        config: NotificationConfig | None = None,
        channel_name: str = "in_app",
    ) -> None:
        super().__init__(config or NotificationConfig(), channel_name)
        self._storage: Any = None
        self._broadcaster: Any = None

    def bind_storage(self, storage: Any) -> None:
        """Bind the SQLite notification storage instance."""
        self._storage = storage

    def bind_broadcaster(self, broadcaster: Any) -> None:
        """Bind the SSE notification broadcaster instance."""
        self._broadcaster = broadcaster

    async def _do_send(self, payload: NotificationPayload) -> NotificationResult:
        severity = _PRIORITY_SEVERITY_MAP.get(payload.priority, "info")
        notif_type = _EVENT_TYPE_MAP.get(payload.event, "custom")

        # Determine href from metadata if not set
        href = payload.href
        entity_id = payload.entity_id
        entity_type = payload.entity_type

        if not href and entity_type and entity_id:
            if entity_type == "job":
                href = f"/jobs/{entity_id}"
            elif entity_type == "finding":
                href = "/findings"
            elif entity_type == "target":
                href = "/targets"

        # 1. Persist to database
        notif_id = ""
        if self._storage is not None:
            try:
                notif_id = await asyncio.to_thread(
                    self._storage.store,
                    event=payload.event.value,
                    priority=payload.priority.value,
                    title=payload.title,
                    message=payload.message,
                    metadata=payload.metadata,
                    source=payload.source,
                    correlation_id=payload.correlation_id,
                    entity_id=entity_id,
                    entity_type=entity_type,
                    href=href,
                )
            except Exception:
                logger.exception("Failed to persist notification to DB")

        # 2. Broadcast via SSE
        if self._broadcaster is not None:
            notification_event = {
                "id": notif_id or f"notif-live-{payload.timestamp.timestamp():.0f}",
                "type": notif_type,
                "severity": severity,
                "title": payload.title,
                "message": payload.message,
                "source": payload.source,
                "href": href,
                "entity_id": entity_id,
                "entity_type": entity_type,
                "timestamp": payload.timestamp.timestamp() * 1000,
                "read": False,
                "event": payload.event.value,
            }
            try:
                await self._broadcaster.broadcast(notification_event)
            except Exception:
                logger.exception("Failed to broadcast notification via SSE")

        return NotificationResult(
            success=True,
            channel=self._channel_name,
            event=payload.event.value,
            priority=payload.priority.value,
        )

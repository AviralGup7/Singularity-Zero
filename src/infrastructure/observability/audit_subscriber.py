"""Event subscriber for security auditing.

Integrates the pipeline event bus with the tamper-evident AuditLogger
to maintain a verifiable audit trail of all security testing activities.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.events import EventBus, EventType, PipelineEvent
from src.infrastructure.security import AuditEvent, AuditLogger, AuditSeverity, SecurityConfig

logger = logging.getLogger(__name__)


class AuditSubscriber:
    """Subscriber that records pipeline events to the security audit log."""

    def __init__(self, event_bus: EventBus, audit_logger: AuditLogger | None = None) -> None:
        self._event_bus = event_bus
        self._audit_logger = audit_logger or AuditLogger(SecurityConfig())
        self._subscription_ids: list[str] = []

    def start(self) -> None:
        """Start listening for events to audit."""
        if self._subscription_ids:
            return

        mappings = {
            EventType.PIPELINE_STARTED: (self._on_pipeline_started, AuditEvent.PIPELINE_START),
            EventType.STAGE_STARTED: (self._on_stage_started, AuditEvent.STAGE_START),
            EventType.STAGE_COMPLETED: (self._on_stage_completed, AuditEvent.STAGE_COMPLETED),
            EventType.STAGE_FAILED: (self._on_stage_failed, AuditEvent.STAGE_FAILED),
            EventType.FINDING_CREATED: (self._on_finding_discovered, AuditEvent.FINDING_DISCOVERED),
            EventType.PIPELINE_COMPLETE: (
                self._on_pipeline_completed,
                AuditEvent.PIPELINE_COMPLETED,
            ),
            EventType.PIPELINE_ERROR: (self._on_pipeline_failed, AuditEvent.PIPELINE_FAILED),
        }

        for event_type, (handler, _) in mappings.items():
            sub_id = self._event_bus.subscribe(event_type, handler)
            self._subscription_ids.append(sub_id)

    def stop(self) -> None:
        """Stop listening for events."""
        for sub_id in self._subscription_ids:
            self._event_bus.unsubscribe(sub_id)
        self._subscription_ids.clear()

    def _log(
        self,
        event: AuditEvent,
        user_id: str = "system",
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
        severity: AuditSeverity | None = None,
        correlation_id: str | None = None,
    ) -> None:
        """Helper to call audit_logger.log safely."""
        try:
            self._audit_logger.log(
                event=event,
                user_id=user_id,
                resource_id=resource_id,
                details=details,
                severity=severity or event.default_severity,
                correlation_id=correlation_id,
            )
        except Exception:
            logger.exception("Failed to record audit entry for event %s", event.value)

    def _on_pipeline_started(self, event: PipelineEvent) -> None:
        self._log(
            AuditEvent.PIPELINE_START,
            resource_id=event.data.get("target"),
            details={
                "run_id": event.data.get("run_id"),
                "mode": event.data.get("mode"),
                "args": event.data.get("args"),
            },
            correlation_id=event.correlation_id,
        )

    def _on_stage_started(self, event: PipelineEvent) -> None:
        self._log(
            AuditEvent.STAGE_START,
            resource_id=event.data.get("stage"),
            details={
                "run_id": event.data.get("run_id"),
            },
            correlation_id=event.correlation_id,
        )

    def _on_stage_completed(self, event: PipelineEvent) -> None:
        self._log(
            AuditEvent.STAGE_COMPLETED,
            resource_id=event.data.get("stage"),
            details={
                "run_id": event.data.get("run_id"),
                "duration": event.data.get("duration_seconds"),
            },
            correlation_id=event.correlation_id,
        )

    def _on_stage_failed(self, event: PipelineEvent) -> None:
        self._log(
            AuditEvent.STAGE_FAILED,
            resource_id=event.data.get("stage"),
            details={
                "run_id": event.data.get("run_id"),
                "error": event.data.get("error"),
            },
            severity=AuditSeverity.WARNING,
            correlation_id=event.correlation_id,
        )

    def _on_finding_discovered(self, event: PipelineEvent) -> None:
        self._log(
            AuditEvent.FINDING_DISCOVERED,
            resource_id=f"{event.data.get('category')}:{event.data.get('url')}",
            details={
                "run_id": event.data.get("run_id"),
                "severity": event.data.get("severity"),
            },
            correlation_id=event.correlation_id,
        )

    def _on_pipeline_completed(self, event: PipelineEvent) -> None:
        self._log(
            AuditEvent.PIPELINE_COMPLETED,
            resource_id=event.data.get("target"),
            details={
                "run_id": event.data.get("run_id"),
                "findings": event.data.get("total_findings"),
            },
            correlation_id=event.correlation_id,
        )

    def _on_pipeline_failed(self, event: PipelineEvent) -> None:
        self._log(
            AuditEvent.PIPELINE_FAILED,
            resource_id=event.data.get("target"),
            details={
                "run_id": event.data.get("run_id"),
                "reason": event.data.get("reason"),
            },
            severity=AuditSeverity.ERROR,
            correlation_id=event.correlation_id,
        )


def register_audit_subscriber(
    event_bus: EventBus, audit_logger: AuditLogger | None = None
) -> AuditSubscriber:
    """Helper to create and start an audit subscriber."""
    subscriber = AuditSubscriber(event_bus, audit_logger)
    subscriber.start()
    return subscriber

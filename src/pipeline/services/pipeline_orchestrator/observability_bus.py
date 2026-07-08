"""Manages registering of subscribers and emitting events."""

import logging
from typing import Any

from src.core.contracts.pipeline_runtime import PipelineInput
from src.core.events import EVENT_SCHEMA_VERSION, EventBus, EventType
from src.infrastructure.notifications.manager import ManagerConfig, NotificationManager
from src.infrastructure.observability.audit_subscriber import register_audit_subscriber
from src.infrastructure.observability.event_subscribers import register_event_metrics_subscribers
from src.infrastructure.observability.learning_subscriber import register_learning_subscriber
from src.infrastructure.observability.notification_subscriber import (
    register_notification_subscriber,
)
from src.infrastructure.observability.progress_subscriber import register_progress_subscriber
from src.learning.integration import LearningIntegration

logger = logging.getLogger(__name__)


class ObservabilityBus:
    """Manages registering of subscribers (event metrics, progress, audit, notification, learning) and emitting events."""

    def __init__(
        self, event_bus: EventBus, notification_manager: NotificationManager | None = None
    ) -> None:
        self._event_bus = event_bus
        register_event_metrics_subscribers(self._event_bus)
        register_progress_subscriber(self._event_bus)
        register_audit_subscriber(self._event_bus)

        if notification_manager is not None:
            self.notification_manager = notification_manager
        else:
            self.notification_manager = NotificationManager(ManagerConfig())
        register_notification_subscriber(self._event_bus, self.notification_manager)

        self.learning_integration = LearningIntegration.get_or_create()
        try:
            register_learning_subscriber(self._event_bus, self.learning_integration)
        except Exception as exc:
            logger.warning("Failed to register learning subscriber: %s", exc)
            try:
                self.learning_integration.close()
            except Exception:
                logger.warning("Operation failed in observability_bus.py", exc_info=True)
            self.learning_integration = LearningIntegration.get_or_create()

    def emit_event(
        self,
        event_type: EventType,
        source: str,
        data: dict[str, Any],
        pipeline_input: PipelineInput | None,
        correlation_id: str,
        trace_id: str | None = None,
    ) -> None:
        enriched_data = {
            "event_schema_version": EVENT_SCHEMA_VERSION,
            **(data or {}),
        }
        if pipeline_input:
            enriched_data.setdefault("target", pipeline_input.target_name)
            enriched_data.setdefault("target_name", pipeline_input.target_name)
            enriched_data.setdefault("run_id", pipeline_input.run_id)

        self._event_bus.emit(
            event_type=event_type,
            source=source,
            data=enriched_data,
            correlation_id=correlation_id,
            trace_id=trace_id,
        )

"""Event subscriber for the learning feedback loop.

Integrates the pipeline event bus with the LearningIntegration service
to record telemetry and compute adaptations from scan results.
"""

from __future__ import annotations

import logging

from src.core.events import EventBus, EventType, PipelineEvent
from src.learning.integration import LearningIntegration

logger = logging.getLogger(__name__)


class LearningSubscriber:
    """Subscriber that feeds pipeline events into the learning subsystem."""

    def __init__(self, event_bus: EventBus, integration: LearningIntegration) -> None:
        self._event_bus = event_bus
        self._integration = integration
        self._subscription_ids: list[str] = []

    def start(self) -> None:
        """Start listening for events to feed learning."""
        if self._subscription_ids:
            return

        # Phase 2 & 3 from LearningIntegration are best handled at pipeline end
        mappings = {
            EventType.PIPELINE_COMPLETE: self._on_pipeline_complete,
        }

        for event_type, handler in mappings.items():
            sub_id = self._event_bus.subscribe_async(event_type, handler)
            self._subscription_ids.append(sub_id)

    def stop(self) -> None:
        """Stop listening for events."""
        for sub_id in self._subscription_ids:
            self._event_bus.unsubscribe(sub_id)
        self._subscription_ids.clear()

    async def _on_pipeline_complete(self, event: PipelineEvent) -> None:
        """Execute learning update when pipeline completes successfully."""
        try:
            ctx = event.data.get("ctx", {})
            if not ctx:
                logger.warning("No context found in PIPELINE_COMPLETE event for learning")
                return

            await self._integration.run_learning_update(ctx)
        except Exception:
            logger.exception("Failed to run learning update for event %s", event.event_type.value)


def register_learning_subscriber(
    event_bus: EventBus, integration: LearningIntegration
) -> LearningSubscriber:
    """Helper to create and start a learning subscriber."""
    subscriber = LearningSubscriber(event_bus, integration)
    subscriber.start()
    return subscriber

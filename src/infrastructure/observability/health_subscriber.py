"""Event subscriber wiring the self-healing controller to the EventBus.

This module mirrors the ``register_progress_subscriber`` / ``register_audit_subscriber``
pattern so the dashboard and pipeline orchestrator can declaratively bind
the reactive :class:`SelfHealingController` to the typed
``HEALTH_METRIC_EMITTED`` event channel.

Probes publish :class:`HealthMetric` events; the subscriber forwards them
into the controller for classification and corrective-action dispatch. There
is no polling loop in the controller itself -- probe cadence is owned by
the subsystems or by callers invoking ``controller.collect_probe_metrics()``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.core.events import EventBus, EventType

if TYPE_CHECKING:
    from src.pipeline.self_healing.controller import SelfHealingController

logger = logging.getLogger(__name__)


class HealthSubscriber:
    """Subscribes a :class:`SelfHealingController` to ``HEALTH_METRIC_EMITTED`` events."""

    def __init__(self, event_bus: EventBus, controller: SelfHealingController) -> None:
        self._event_bus = event_bus
        self._controller = controller
        self._subscription_id: str | None = None

    def start(self) -> None:
        """Bind the controller to the bus (idempotent)."""
        if self._subscription_id is not None:
            return
        controller = self._controller
        existing_bus = getattr(controller, "_event_bus", None)
        if existing_bus is not None and existing_bus is not self._event_bus:
            logger.debug(
                "HealthSubscriber overriding controller's event bus (%s -> %s)",
                type(existing_bus).__name__,
                type(self._event_bus).__name__,
            )
        controller._event_bus = self._event_bus  # noqa: SLF001 -- intentional binding
        self._subscription_id = controller.subscribe_event_bus(self._event_bus)
        logger.info(
            "HealthSubscriber bound: event_type=%s subscription_id=%s",
            EventType.HEALTH_METRIC_EMITTED.value,
            self._subscription_id,
        )

    def stop(self) -> None:
        """Tear down the subscription."""
        if self._subscription_id is None:
            return
        try:
            self._event_bus.unsubscribe(self._subscription_id)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.debug("Failed to unsubscribe health subscriber: %s", exc)
        self._subscription_id = None


def register_health_subscriber(
    event_bus: EventBus, controller: SelfHealingController
) -> HealthSubscriber:
    """Create and start a :class:`HealthSubscriber`.

    Mirrors :func:`register_progress_subscriber` and
    :func:`register_learning_subscriber` so callers can compose
    subscribers uniformly. Returns the started subscriber so it can be
    stopped later if the controller is ever torn down.
    """
    subscriber = HealthSubscriber(event_bus, controller)
    subscriber.start()
    return subscriber

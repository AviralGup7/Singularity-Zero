"""Event-driven pipeline stage communication system."""

import asyncio
import inspect
import logging
import threading
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

EVENT_SCHEMA_VERSION = "v1"


class EventType(StrEnum):
    """Event types for pipeline stage communication."""

    PIPELINE_STARTED = "pipeline_started"
    STAGE_STARTED = "stage_started"
    STAGE_PROGRESS = "stage_progress"
    STAGE_RETRY = "stage_retry"
    STAGE_COMPLETED = "stage_completed"
    STAGE_SKIPPED = "stage_skipped"
    FINDING_CREATED = "finding_created"
    FINDING_DISCOVERED = "finding_discovered"
    STAGE_FAILED = "stage_failed"
    PIPELINE_COMPLETE = "pipeline_complete"
    PIPELINE_ERROR = "pipeline_error"


@dataclass
class PipelineEvent:
    """Represents an event in the pipeline lifecycle."""

    event_type: EventType
    schema_version: str = EVENT_SCHEMA_VERSION
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class EventBus:
    """Thread-safe event bus with pub/sub pattern and async support."""

    def __init__(self) -> None:
        self._subscribers: dict[EventType, dict[str, Callable[..., Any]]] = defaultdict(dict)
        self._async_queue: asyncio.Queue[PipelineEvent] | None = None
        self._lock = threading.Lock()
        self._running = False
        self._async_handlers: list[Callable[..., Any]] = []
        self._pending_tasks: set[asyncio.Task[Any]] = set()

    def subscribe(self, event_type: EventType, handler: Callable[..., Any]) -> str:
        """Subscribe to an event type. Returns subscription_id."""
        subscription_id = str(uuid.uuid4())
        with self._lock:
            self._subscribers[event_type][subscription_id] = handler
        logger.debug("Subscribed handler %s to event %s", subscription_id, event_type.value)
        return subscription_id

    def subscribe_async(self, event_type: EventType, handler: Callable[..., Any]) -> str:
        """Subscribe an async handler to an event type. Returns subscription_id."""
        subscription_id = str(uuid.uuid4())
        with self._lock:
            self._subscribers[event_type][subscription_id] = handler
            if handler not in self._async_handlers:
                self._async_handlers.append(handler)
        logger.debug("Subscribed async handler %s to event %s", subscription_id, event_type.value)
        return subscription_id

    def unsubscribe(self, subscription_id: str) -> None:
        """Remove a subscription by its ID."""
        with self._lock:
            for event_type in list(self._subscribers.keys()):
                if subscription_id in self._subscribers[event_type]:
                    del self._subscribers[event_type][subscription_id]
                    logger.debug("Unsubscribed %s from event %s", subscription_id, event_type.value)
                    return
        logger.warning("Subscription %s not found", subscription_id)

    def publish(self, event: PipelineEvent) -> None:
        """Publish event to all subscribers (fire-and-forget)."""
        handlers = self._get_handlers(event.event_type)
        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    self._schedule_async(handler, event)
                else:
                    handler(event)
            except (AttributeError, TypeError, ValueError, RuntimeError):
                logger.warning(
                    "Handler error processing event %s from %s",
                    event.event_type.value,
                    event.source,
                    exc_info=True,
                )

    def emit(
        self,
        event_type: EventType,
        *,
        source: str = "",
        data: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> PipelineEvent:
        """Create and publish a pipeline event in one call."""
        event = PipelineEvent(
            event_type=event_type,
            source=source,
            data={
                "event_schema_version": EVENT_SCHEMA_VERSION,
                **(data or {}),
            },
            correlation_id=correlation_id or str(uuid.uuid4()),
        )
        self.publish(event)
        return event

    def publish_sync(self, event: PipelineEvent) -> list[Any]:
        """Publish event and collect handler results.

        Async handlers are executed synchronously when no loop is running so
        their resolved values can be returned to callers that need a deterministic
        result list.
        """
        results: list[Any] = []
        handlers = self._get_handlers(event.event_type)
        for handler in handlers:
            try:
                if inspect.iscoroutinefunction(handler):
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        results.append(asyncio.run(handler(event)))
                    else:
                        task = loop.create_task(handler(event))
                        self._track_task(task)
                        results.append(None)
                else:
                    result = handler(event)
                    results.append(result)
            except (AttributeError, TypeError, ValueError, RuntimeError):
                logger.warning(
                    "Handler error processing sync event %s from %s",
                    event.event_type.value,
                    event.source,
                    exc_info=True,
                )
                results.append(None)
        return results

    async def publish_async(self, event: PipelineEvent) -> None:
        """Publish event to async handlers via queue."""
        if self._async_queue is None:
            self._async_queue = asyncio.Queue()
        await self._async_queue.put(event)

    async def start_async_consumer(self) -> None:
        """Start consuming events from the async queue."""
        self._running = True
        while self._running:
            try:
                if self._async_queue is None:
                    self._async_queue = asyncio.Queue()
                event = await asyncio.wait_for(self._async_queue.get(), timeout=1.0)
                handlers = self._get_handlers(event.event_type)
                for handler in handlers:
                    if inspect.iscoroutinefunction(handler):
                        try:
                            await handler(event)
                        except (AttributeError, TypeError, ValueError, RuntimeError):
                            logger.warning(
                                "Async handler error processing event %s from %s",
                                event.event_type.value,
                                event.source,
                            )
                self._async_queue.task_done()
            except TimeoutError:
                continue
            except (AttributeError, TypeError, ValueError, RuntimeError):
                logger.warning("Error in async consumer loop")

    async def flush_pending(self, timeout: float = 2.0) -> None:
        """Wait for currently scheduled async handlers to finish."""
        pending = [task for task in self._pending_tasks if not task.done()]
        if not pending:
            return
        try:
            await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True), timeout=timeout
            )
        except TimeoutError:
            for task in pending:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    def stop_async_consumer(self) -> None:
        """Stop the async consumer loop."""
        self._running = False

    def _get_handlers(self, event_type: EventType) -> list[Callable[..., Any]]:
        """Get all handlers for an event type (thread-safe)."""
        with self._lock:
            return list(self._subscribers.get(event_type, {}).values())

    def _schedule_async(self, handler: Callable[..., Any], event: PipelineEvent) -> None:
        """Schedule an async handler for execution."""
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(handler(event))
            self._track_task(task)
        except RuntimeError:
            threading.Thread(
                target=asyncio.run,
                args=(handler(event),),
                daemon=True,
            ).start()

    def _track_task(self, task: asyncio.Task[Any]) -> None:
        self._pending_tasks.add(task)
        task.add_done_callback(self._pending_tasks.discard)

    def clear(self) -> None:
        """Clear all subscriptions."""
        with self._lock:
            self._subscribers.clear()
            self._async_handlers.clear()


_default_event_bus: EventBus | None = None
_default_event_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    """Return a process-wide event bus instance for intra-pipeline events."""
    global _default_event_bus
    with _default_event_bus_lock:
        if _default_event_bus is None:
            _default_event_bus = EventBus()
        return _default_event_bus


def reset_event_bus() -> None:
    """Reset the process-wide event bus (primarily used in tests)."""
    global _default_event_bus
    with _default_event_bus_lock:
        _default_event_bus = None

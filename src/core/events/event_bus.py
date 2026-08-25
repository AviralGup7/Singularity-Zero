from __future__ import annotations

import asyncio
import contextvars
import inspect
import json
import logging
import threading
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

EVENT_SCHEMA_VERSION = "v1"


class EventType(StrEnum):
    """Event types for pipeline stage communication."""

    PIPELINE_STARTED = "pipeline_started"
    STAGE_STARTED = "stage_started"
    STAGE_PROGRESS = "stage_progress"
    STAGE_RETRY = "stage_retry"
    STAGE_COMPLETED = "stage_completed"
    STAGE_SKIPPED = "stage_skipped"
    STAGE_TELEMETRY = "stage_telemetry"
    FINDING_CREATED = "finding_created"
    FINDING_DISCOVERED = "finding_discovered"
    STAGE_FAILED = "stage_failed"
    PIPELINE_COMPLETE = "pipeline_complete"
    PIPELINE_ERROR = "pipeline_error"
    PIPELINE_CANCELLED = "pipeline_cancelled"
    GHOST_ACTOR_MIGRATED = "ghost_actor_migrated"
    GHOST_ACTOR_EVACUATED = "ghost_actor_evacuated"
    INGRESS_POLICY_RESULT = "ingress_policy_result"
    HEALTH_METRIC_EMITTED = "health_metric_emitted"
    RECON_DEGRADED = "recon_degraded"


@dataclass
class PipelineEvent:
    """Represents an event in the pipeline lifecycle."""

    event_type: EventType
    schema_version: str = "v1"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class Event:
    """Immutable event with metadata."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    type: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = ""
    payload: dict = field(default_factory=dict)
    correlation_id: str = ""
    trace_id: str = ""

    def to_json(self) -> str:
        return json.dumps(
            {
                "id": self.id,
                "type": self.type,
                "timestamp": self.timestamp.isoformat(),
                "source": self.source,
                "payload": self.payload,
                "correlation_id": self.correlation_id,
                "trace_id": self.trace_id,
            }
        )

    @classmethod
    def from_json(cls, data: str) -> Event:
        d = json.loads(data)
        d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        return cls(**d)


class EventHandler(ABC):
    """Base class for event handlers."""

    @property
    @abstractmethod
    def event_types(self) -> list[str]:
        """Event types this handler subscribes to."""
        ...

    @abstractmethod
    async def handle(self, event: Event) -> None:
        """Process an event."""
        ...


@dataclass
class Subscription:
    handler: EventHandler
    event_types: list[str]
    filter_fn: Callable[[Event], bool] | None = None


class EventBus:
    """In-process notification dispatcher — not a source of truth (I32).

    Authoritative facts are SettlementIntent / PartitionWAL / DurableOutbox.
    This bus delivers already-committed notifications to in-process observers.
    A handler exception or fan-out drop does not un-commit settlement.

    Pipeline: Authoritative Event → Durable Outbox → this dispatcher → consumers.

    Recursive ``emit``/``publish_sync`` depth is capped; finding and
    pipeline-terminal events are never dropped by that cap.
    """

    _FANOUT_MAX_DEPTH = 5
    _CRITICAL_EVENT_TYPES: frozenset[str] = frozenset(
        {
            EventType.FINDING_CREATED.value,
            EventType.FINDING_DISCOVERED.value,
            EventType.PIPELINE_COMPLETE.value,
            EventType.PIPELINE_ERROR.value,
        }
    )

    def __init__(self, max_queue_size: int = 10000):
        self._subscriptions: dict[str, list[Subscription]] = defaultdict(list)
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=max_queue_size)
        self._dlq: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False
        self._task: asyncio.Task | None = None
        self._lock = asyncio.Lock()
        self._metrics = {
            "published": 0,
            "delivered": 0,
            "failed": 0,
            "dlq_size": 0,
            "dropped_fanout": 0,
        }
        self._depth: contextvars.ContextVar[int] = contextvars.ContextVar(
            "event_bus_depth", default=0
        )

    def subscribe(self, arg1: Any, arg2: Any = None) -> None:
        """Register a handler for event types."""
        if callable(arg2):
            et_str = getattr(arg1, "value", str(arg1))
            self._subscriptions[et_str].append(Subscription(handler=arg2, event_types=[et_str]))
            return
        handler = arg1
        event_types = arg2
        types = (
            event_types
            if isinstance(event_types, (list, tuple, set))
            else (getattr(handler, "event_types", None) or [])
        )
        for et in types:
            et_str = getattr(et, "value", str(et))
            self._subscriptions[et_str].append(
                Subscription(handler=handler, event_types=list(types))
            )

    def unsubscribe(self, target: EventHandler | str) -> None:
        """Remove all subscriptions for a handler or subscription_id."""
        for subs in self._subscriptions.values():
            subs[:] = [
                s for s in subs if s.handler is not target and getattr(s, "sub_id", None) != target
            ]

    def subscribe_async(self, event_type: Any, handler: Callable[..., Any]) -> str:
        """Subscribe an async handler function."""
        sub_id = str(uuid.uuid4())
        et_str = getattr(event_type, "value", str(event_type))
        sub = Subscription(handler=handler, event_types=[et_str])
        sub.sub_id = sub_id  # type: ignore[attr-defined]
        self._subscriptions[et_str].append(sub)
        return sub_id

    def emit(
        self,
        event_type: Any,
        *,
        source: str = "",
        data: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> PipelineEvent:
        """Create and publish a pipeline event."""
        enriched = dict(data or {})
        if trace_id:
            enriched["trace_id"] = trace_id
        event = PipelineEvent(
            event_type=event_type,
            source=source,
            data=enriched,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )
        self.publish_sync(event)
        return event

    def _event_type_value(self, event: Any) -> str:
        return str(
            getattr(getattr(event, "event_type", None), "value", None)
            or getattr(event, "type", "")
            or ""
        )

    def _is_critical(self, event: Any) -> bool:
        return self._event_type_value(event) in self._CRITICAL_EVENT_TYPES

    def dropped_status(self) -> dict[str, int]:
        """Counters for events dropped by the live emit path."""
        return {"dropped_fanout": int(self._metrics.get("dropped_fanout", 0))}

    def publish_sync(self, event: Any) -> list[Any]:
        """Synchronous publish fallback."""
        depth = int(self._depth.get(0))
        if depth >= self._FANOUT_MAX_DEPTH and not self._is_critical(event):
            self._metrics["dropped_fanout"] = int(self._metrics.get("dropped_fanout", 0)) + 1
            logger.warning(
                "Event fan-out depth %d exceeded; dropping non-critical %s",
                depth,
                self._event_type_value(event),
            )
            return []
        token = self._depth.set(depth + 1)
        try:
            return self._dispatch_sync(event)
        finally:
            self._depth.reset(token)

    def _dispatch_sync(self, event: Any) -> list[Any]:
        results = []
        et_str = self._event_type_value(event)
        subs = list(self._subscriptions.get(et_str, []))
        for sub in subs:
            try:
                if callable(sub.handler):
                    res = sub.handler(event)
                    if inspect.iscoroutine(res):
                        try:
                            loop = asyncio.get_running_loop()
                            task = loop.create_task(res)
                            if not hasattr(self, "_pending_tasks"):
                                self._pending_tasks = set()
                            self._pending_tasks.add(task)
                            task.add_done_callback(self._pending_tasks.discard)
                            results.append(task)
                        except RuntimeError:
                            res = asyncio.run(res)
                            results.append(res)
                    else:
                        results.append(res)
                elif hasattr(sub.handler, "handle"):
                    try:
                        loop = asyncio.get_running_loop()
                        task = loop.create_task(sub.handler.handle(event))
                        if not hasattr(self, "_pending_tasks"):
                            self._pending_tasks = set()
                        self._pending_tasks.add(task)
                        task.add_done_callback(self._pending_tasks.discard)
                        results.append(task)
                    except RuntimeError:
                        res = asyncio.run(sub.handler.handle(event))
                        results.append(res)
            except Exception as exc:
                logger.warning("Error in sync publish handler: %s", exc)
                results.append(None)
        return results

    async def flush_pending(self, timeout: float = 2.0) -> None:
        """Wait for pending tasks to complete."""
        if hasattr(self, "_pending_tasks") and self._pending_tasks:
            pending = list(self._pending_tasks)
            self._pending_tasks.clear()
            await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.sleep(0)

    def clear(self) -> None:
        """Clear all subscriptions."""
        self._subscriptions.clear()

    def _get_handlers(self, event_type: Any) -> list[Callable[..., Any]]:
        """Return handlers for an event type."""
        et_str = getattr(event_type, "value", str(event_type))
        return [sub.handler for sub in self._subscriptions.get(et_str, [])]

    async def publish(self, event: Any) -> bool:
        """Publish an event."""
        if self._running:
            try:
                self._queue.put_nowait(event)
                self._metrics["published"] += 1
                return True
            except asyncio.QueueFull:
                self._metrics["failed"] += 1
                return False
        # Direct dispatch fallback when background loop is not started
        return await self.publish_and_wait(event)

    async def publish_and_wait(self, event: Any, timeout: float = 5.0) -> bool:
        """Publish and wait for all handlers to complete."""
        self._metrics["published"] += 1
        tasks = []
        et_val = str(
            getattr(getattr(event, "event_type", None), "value", None)
            or getattr(event, "type", "")
            or getattr(event, "event_type", "")
            or ""
        )
        for et in [et_val, "*"]:
            for sub in self._subscriptions.get(et, []):
                if sub.filter_fn is None or sub.filter_fn(event):
                    tasks.append(asyncio.create_task(self._safe_handle(sub, event)))
        if not tasks:
            return True
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), timeout=timeout
            )
        except TimeoutError:
            self._metrics["failed"] += 1
            return False
        if any(isinstance(item, BaseException) for item in results):
            self._metrics["failed"] += 1
            return False
        self._metrics["delivered"] += 1
        return True

    async def _safe_handle(self, sub: Subscription, event: Event) -> None:
        try:
            handler = sub.handler
            if hasattr(handler, "handle"):
                result = handler.handle(event)
            elif callable(handler):
                result = handler(event)
            else:
                raise TypeError(f"unusable event handler: {handler!r}")
            if inspect.isawaitable(result):
                await result
        except Exception:
            self._metrics["failed"] += 1
            self._dlq.put_nowait(event)

    async def start(self) -> None:
        """Start the event dispatcher."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._dispatch_loop())

    async def stop(self) -> None:
        """Stop the event dispatcher."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _dispatch_loop(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except TimeoutError:
                continue

            tasks = []
            for et in [event.type, "*"]:
                for sub in self._subscriptions.get(et, []):
                    if sub.filter_fn is None or sub.filter_fn(event):
                        tasks.append(asyncio.create_task(self._safe_handle(sub, event)))

            if tasks:
                await asyncio.gather(*tasks)
            self._metrics["delivered"] += 1

    def get_metrics(self) -> dict:
        return {
            **self._metrics,
            "queue_size": self._queue.qsize(),
            "dlq_size": self._dlq.qsize(),
        }


# ---------------------------------------------------------------------------
# Temporary compatibility shim — remove after all callers migrate to DI.
# ---------------------------------------------------------------------------

_event_bus: EventBus | None = None
_event_bus_lock = threading.Lock()


def get_event_bus() -> EventBus:
    global _event_bus
    with _event_bus_lock:
        if _event_bus is None:
            _event_bus = EventBus()
        return _event_bus


def reset_event_bus() -> None:
    global _event_bus
    with _event_bus_lock:
        _event_bus = None

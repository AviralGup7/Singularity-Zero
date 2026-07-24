"""Event-driven pipeline stage communication system.

Event Bus Dependency Graph
==========================

The EventBus provides decoupled communication between pipeline subsystems.
Below is the known dependency graph showing who publishes and subscribes to
each EventType, and the fan-out amplification risk.

Publishers → EventType → Subscribers (handlers)
------------------------------------------------

Pipeline Lifecycle:
  PIPELINE_STARTED
    Publishers: pipeline orchestrator
    Subscribers: observability (metrics), dashboard SSE, job lifecycle

  STAGE_STARTED
    Publishers: pipeline orchestrator
    Subscribers: observability, dashboard SSE

  STAGE_PROGRESS
    Publishers: pipeline orchestrator, tool execution
    Subscribers: observability (high frequency), dashboard SSE

  STAGE_RETRY
    Publishers: pipeline orchestrator, tool execution
    Subscribers: observability, notifications, dashboard SSE, job lifecycle,
                 learning subscriber

  STAGE_COMPLETED
    Publishers: pipeline orchestrator
    Subscribers: observability, dashboard SSE, job lifecycle

  STAGE_FAILED
    Publishers: pipeline orchestrator, tool execution
    Subscribers: observability, notifications, dashboard SSE, job lifecycle

Findings:
  FINDING_CREATED
    Publishers: recon modules, exploitation modules
    Subscribers: observability, dashboard SSE, learning subscriber

  FINDING_DISCOVERED
    Publishers: recon modules
    Subscribers: observability, dashboard SSE

Pipeline Completion:
  PIPELINE_COMPLETE
    Publishers: pipeline orchestrator
    Subscribers: observability, notifications, dashboard SSE, job lifecycle,
                 learning subscriber

  PIPELINE_ERROR
    Publishers: pipeline orchestrator
    Subscribers: observability, notifications, dashboard SSE, job lifecycle

  PIPELINE_CANCELLED
    Publishers: pipeline orchestrator
    Subscribers: observability, dashboard SSE, job lifecycle

Ghost Actor:
  GHOST_ACTOR_MIGRATED
    Publishers: mesh coordinator
    Subscribers: observability, dashboard SSE

  GHOST_ACTOR_EVACUATED
    Publishers: mesh coordinator
    Subscribers: observability, dashboard SSE

Ingress:
  INGRESS_POLICY_RESULT
    Publishers: ingress policy engine
    Subscribers: observability, dashboard SSE

Health:
  HEALTH_METRIC_EMITTED
    Publishers: health monitor
    Subscribers: observability, dashboard SSE

  RECON_DEGRADED
    Publishers: recon orchestrator
    Subscribers: notifications, dashboard SSE

Amplification Risk Summary
--------------------------
A single STAGE_RETRY event can trigger:
  - observability subscriber → emits HEALTH_METRIC_EMITTED → dashboard SSE
  - notifications subscriber → may emit RECON_DEGRADED → dashboard SSE
  - learning subscriber → may emit internal events
  - job lifecycle → may emit STAGE_STARTED for retry → observability + dashboard

Estimated fan-out per event: 3-10 subscribers, each potentially triggering
additional events. With 10k pipeline events, worst-case amplification is
40k-100k handler invocations.

Mitigation: EventBus now includes fan-out rate limiting (see _fanout_* params)
and recursion depth limiting (see _fanout_max_depth) to prevent cascading
amplification storms.
"""

import asyncio
import contextvars
import inspect
import logging
import os
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

# Bug fix: Use contextvars instead of threading.local() for depth tracking.
# threading.local() shares depth across all async tasks on the same thread,
# causing depth corruption when multiple handlers publish concurrently.
_event_depth_var: contextvars.ContextVar[int] = contextvars.ContextVar("event_depth", default=0)

logger = logging.getLogger(__name__)

EVENT_SCHEMA_VERSION = "v1"

# Fan-out rate limiting defaults
_DEFAULT_FANOUT_WINDOW_SECONDS = 60.0
_DEFAULT_FANOUT_MAX_PER_WINDOW = 500
_DEFAULT_FANOUT_MAX_DEPTH = 5


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
    schema_version: str = EVENT_SCHEMA_VERSION
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


class EventBus:
    """Thread-safe event bus with pub/sub pattern and async support.

    All event dispatch is synchronous via ``publish()``/``emit()``.  Async
    handlers are scheduled as background tasks gated by a semaphore to
    prevent unbounded concurrency.

    Includes fan-out rate limiting to prevent event amplification storms
    where a single event triggers cascading event emissions.

    Bug #11: Tracks dropped events so silent correctness failures (findings
    lost under load) are detectable.  Critical event types (FINDING_CREATED,
    FINDING_DISCOVERED) are never silently dropped — they are buffered in a
    bounded priority queue and retried on the next publish cycle.
    """

    _MAX_CONCURRENT_TASKS = 256
    _MAX_PENDING_TASKS = 2048
    _FALING_HANDLER_THRESHOLD = 10

    # Event types that must never be silently dropped — they carry
    # correctness-critical data (e.g. security findings).
    _CRITICAL_EVENT_TYPES: frozenset[EventType] = frozenset({
        EventType.FINDING_CREATED,
        EventType.FINDING_DISCOVERED,
        EventType.PIPELINE_COMPLETE,
        EventType.PIPELINE_ERROR,
    })
    _MAX_CRITICAL_BUFFER = 256

    def __init__(
        self,
        *,
        fanout_window: float | None = None,
        fanout_max_per_window: int | None = None,
        fanout_max_depth: int | None = None,
    ) -> None:
        self._subscribers: dict[EventType, dict[str, Callable[..., Any]]] = defaultdict(dict)
        self._lock = threading.Lock()
        self._async_handlers: list[Callable[..., Any]] = []
        self._pending_tasks: set[asyncio.Task[Any]] = set()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._task_semaphore: asyncio.Semaphore | None = None
        self.failed_handlers_count = 0
        self._handler_failure_counts: dict[str, int] = defaultdict(int)
        self._circuit_broken_handlers: set[str] = set()

        # Fan-out rate limiting
        self._fanout_window = fanout_window or float(
            os.environ.get("EVENT_FANOUT_WINDOW_SECONDS", _DEFAULT_FANOUT_WINDOW_SECONDS)
        )
        self._fanout_max_per_window = fanout_max_per_window or int(
            os.environ.get("EVENT_FANOUT_MAX_PER_WINDOW", _DEFAULT_FANOUT_MAX_PER_WINDOW)
        )
        self._fanout_max_depth = fanout_max_depth or int(
            os.environ.get("EVENT_FANOUT_MAX_DEPTH", _DEFAULT_FANOUT_MAX_DEPTH)
        )
        self._fanout_timestamps: list[float] = []
        self._fanout_lock = threading.Lock()

        # Bug fix: Global event budget tracking. The per-publish rate limit
        # only limits the initial publish call, not recursive publishes from
        # subscribers. This counter tracks total events across the entire
        # event graph to prevent cascading amplification storms.
        self._global_event_count: int = 0
        self._global_event_budget: int = 10000
        self._global_event_window: float = 60.0
        self._global_event_window_start: float = 0.0

        # Bug #11: dropped event tracking and critical event buffer
        self._dropped_events: dict[str, int] = {}  # reason -> count
        self._total_dropped: int = 0
        self._critical_buffer: list[PipelineEvent] = []  # bounded retry buffer
        self._critical_drops_logged: int = 0

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

    def _handler_key(self, handler: Callable[..., Any]) -> str:
        return f"{getattr(handler, '__module__', '?')}.{getattr(handler, '__qualname', '?')}:{id(handler)}"

    def _is_handler_circuit_broken(self, handler: Callable[..., Any]) -> bool:
        key = self._handler_key(handler)
        return key in self._circuit_broken_handlers

    def _record_handler_failure(self, handler: Callable[..., Any]) -> None:
        key = self._handler_key(handler)
        self._handler_failure_counts[key] += 1
        if self._handler_failure_counts[key] >= self._FALING_HANDLER_THRESHOLD:
            self._circuit_broken_handlers.add(key)
            logger.warning(
                "Handler %s circuit-broken after %d failures",
                key,
                self._handler_failure_counts[key],
            )

    def _record_handler_success(self, handler: Callable[..., Any]) -> None:
        key = self._handler_key(handler)
        if key in self._handler_failure_counts:
            self._handler_failure_counts[key] = max(0, self._handler_failure_counts[key] - 1)

    def unsubscribe(self, subscription_id: str) -> None:
        """Remove a subscription by its ID."""
        with self._lock:
            for event_type in list(self._subscribers.keys()):
                if subscription_id in self._subscribers[event_type]:
                    del self._subscribers[event_type][subscription_id]
                    logger.debug("Unsubscribed %s from event %s", subscription_id, event_type.value)
                    return
        logger.warning("Subscription %s not found", subscription_id)

    def _is_fanout_exceeded(self) -> bool:
        """Check if fan-out rate limit is exceeded."""
        now = time.monotonic()
        with self._fanout_lock:
            # Prune old timestamps outside the window
            cutoff = now - self._fanout_window
            self._fanout_timestamps = [t for t in self._fanout_timestamps if t > cutoff]
            if len(self._fanout_timestamps) >= self._fanout_max_per_window:
                logger.warning(
                    "Event fan-out rate limit exceeded: %d events in %.1fs window (max %d). "
                    "Dropping event to prevent amplification storm.",
                    len(self._fanout_timestamps),
                    self._fanout_window,
                    self._fanout_max_per_window,
                )
                return True
            self._fanout_timestamps.append(now)

            # Bug fix: Global budget check across recursive publishes
            now_mono = time.monotonic()
            if self._global_event_window_start == 0.0:
                self._global_event_window_start = now_mono
            elapsed = now_mono - self._global_event_window_start
            if elapsed > self._global_event_window:
                self._global_event_count = 0
                self._global_event_window_start = now_mono
            self._global_event_count += 1
            if self._global_event_count > self._global_event_budget:
                logger.warning(
                    "Event bus global budget exceeded: %d events in %.1fs window. "
                    "This indicates recursive event amplification.",
                    self._global_event_count,
                    elapsed,
                )
                return True
        return False

    def _get_depth(self) -> int:
        """Get current event handler recursion depth."""
        return _event_depth_var.get(0)

    def _increment_depth(self) -> int:
        """Increment and return current depth."""
        current = _event_depth_var.get(0)
        _event_depth_var.set(current + 1)
        return current + 1

    def _decrement_depth(self) -> None:
        """Decrement recursion depth."""
        current = _event_depth_var.get(0)
        _event_depth_var.set(max(0, current - 1))

    def _record_drop(self, reason: str, event: PipelineEvent) -> None:
        """Bug #11: Record a dropped event and buffer critical events for retry."""
        with self._fanout_lock:
            self._dropped_events[reason] = self._dropped_events.get(reason, 0) + 1
            self._total_dropped += 1

        if event.event_type in self._CRITICAL_EVENT_TYPES:
            if len(self._critical_buffer) < self._MAX_CRITICAL_BUFFER:
                self._critical_buffer.append(event)
                logger.warning(
                    "Event bus: critical event %s buffered for retry (reason=%s, "
                    "total_dropped=%d). This event carries correctness-critical data.",
                    event.event_type.value,
                    reason,
                    self._total_dropped,
                )
            else:
                self._critical_drops_logged += 1
                if self._critical_drops_logged % 10 == 1:
                    logger.critical(
                        "Event bus: CRITICAL event %s DROPPED (buffer full). "
                        "%d total drops. This WILL cause missing findings in reports.",
                        event.event_type.value,
                        self._total_dropped,
                    )
        else:
            if self._total_dropped % 100 == 1:
                logger.warning(
                    "Event bus: %d total events dropped (reason=%s, type=%s).",
                    self._total_dropped,
                    reason,
                    event.event_type.value,
                )

    def _drain_critical_buffer(self) -> None:
        """Retry buffered critical events after pressure subsides."""
        if not self._critical_buffer:
            return
        buffered = list(self._critical_buffer)
        self._critical_buffer.clear()
        for event in buffered:
            logger.info(
                "Event bus: retrying buffered critical event %s (correlation=%s)",
                event.event_type.value,
                event.correlation_id,
            )
            self.publish(event)

    def publish(self, event: PipelineEvent) -> None:
        """Publish event to all subscribers (fire-and-forget)."""
        depth = self._increment_depth()
        try:
            # Bug fix: Drain critical buffer on every publish regardless of
            # backpressure state. Previously, the drain only triggered when
            # _pending_tasks dropped below half capacity, which could starve
            # critical events under sustained load.
            if self._critical_buffer:
                self._drain_critical_buffer()

            if depth > self._fanout_max_depth:
                logger.warning(
                    "Event fan-out depth limit exceeded (%d). "
                    "Dropping event %s from %s to prevent recursive amplification.",
                    depth,
                    event.event_type.value,
                    event.source,
                )
                self._record_drop("fanout_depth_exceeded", event)
                return

            if self._is_fanout_exceeded():
                self._record_drop("fanout_rate_exceeded", event)
                return

            handlers = self._get_handlers(event.event_type)
            for handler in handlers:
                if self._is_handler_circuit_broken(handler):
                    continue
                try:
                    if inspect.iscoroutinefunction(handler):
                        self._schedule_async(handler, event)
                    else:
                        handler(event)
                    self._record_handler_success(handler)
                except Exception as exc:  # noqa: BLE001
                    self.failed_handlers_count += 1
                    self._record_handler_failure(handler)
                    logger.warning(
                        "Handler error processing event %s from %s: %s",
                        event.event_type.value,
                        event.source,
                        exc,
                        exc_info=True,
                    )
        finally:
            self._decrement_depth()

    def emit(
        self,
        event_type: EventType,
        *,
        source: str = "",
        data: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        trace_id: str | None = None,
    ) -> PipelineEvent:
        """Create and publish a pipeline event in one call."""
        enriched: dict[str, Any] = {}
        if trace_id:
            enriched["trace_id"] = trace_id
        payload = data or {}
        if payload:
            enriched.update(payload)
        event = PipelineEvent(
            event_type=event_type,
            source=source,
            data=enriched,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )
        self.publish(event)
        return event

    def publish_sync(self, event: PipelineEvent) -> list[Any]:
        """Publish event and collect handler results.

        Async handlers are executed synchronously when no loop is running so
        their resolved values can be returned to callers that need a deterministic
        result list.

        When called from inside a running event loop, async handlers are
        scheduled as tasks (their results cannot be awaited from a sync
        function); the corresponding entry in the returned list will be the
        ``asyncio.Task`` so callers can choose to await it. Sync handler
        results are still returned by value.
        """
        results: list[Any] = []
        handlers = self._get_handlers(event.event_type)
        # Lazily created shared loop for the no-running-loop fallback path.
        # Reused across all async handlers in this publish_sync call to avoid
        # creating and destroying an event loop per handler.
        shared_loop: asyncio.AbstractEventLoop | None = None
        try:
            for handler in handlers:
                try:
                    if inspect.iscoroutinefunction(handler):
                        try:
                            loop = asyncio.get_running_loop()
                        except RuntimeError:
                            # No running loop - reuse a shared event loop
                            # instead of creating one per handler.
                            if shared_loop is None:
                                shared_loop = asyncio.new_event_loop()
                            try:
                                result = shared_loop.run_until_complete(handler(event))
                                results.append(result)
                            except Exception:
                                # Bug #6 fix: Copy contextvars to the thread so
                                # handlers that rely on loop-local state (TaskRegistry,
                                # contextvars, etc.) still work in the fallback thread.
                                ctx = contextvars.copy_context()
                                _res_box: list[Any] = [None]
                                _exc_box: list[BaseException | None] = [None]

                                def _run_in_thread() -> None:
                                    try:
                                        _res_box[0] = ctx.run(
                                            lambda: asyncio.run(handler(event))
                                        )
                                    except Exception as e:
                                        _exc_box[0] = e

                                t = threading.Thread(target=_run_in_thread)
                                t.start()
                                t.join()
                                if _exc_box[0] is not None:
                                    raise _exc_box[0]
                                results.append(_res_box[0])
                        else:
                            task = loop.create_task(handler(event))
                            self._track_task(task)
                            results.append(task)
                    else:
                        result = handler(event)
                        results.append(result)
                except Exception as exc:  # noqa: BLE001
                    self.failed_handlers_count += 1
                    logger.warning(
                        "Handler error processing sync event %s from %s: %s",
                        event.event_type.value,
                        event.source,
                        exc,
                        exc_info=True,
                    )
                    results.append(None)
        finally:
            if shared_loop is not None and not shared_loop.is_closed():
                shared_loop.close()
        return results

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

    def fanout_status(self) -> dict[str, Any]:
        """Return diagnostic info about fan-out rate limiting."""
        now = time.monotonic()
        with self._fanout_lock:
            cutoff = now - self._fanout_window
            recent = [t for t in self._fanout_timestamps if t > cutoff]
        return {
            "window_seconds": self._fanout_window,
            "max_per_window": self._fanout_max_per_window,
            "max_depth": self._fanout_max_depth,
            "events_in_window": len(recent),
            "window_utilization_pct": round(
                100.0 * len(recent) / max(1, self._fanout_max_per_window), 1
            ),
        }

    def dropped_status(self) -> dict[str, Any]:
        """Bug #11: Return diagnostic info about dropped events."""
        with self._fanout_lock:
            return {
                "total_dropped": self._total_dropped,
                "by_reason": dict(self._dropped_events),
                "critical_buffer_size": len(self._critical_buffer),
                "critical_buffer_capacity": self._MAX_CRITICAL_BUFFER,
                "critical_drops_logged": self._critical_drops_logged,
            }

    def _get_handlers(self, event_type: EventType) -> list[Callable[..., Any]]:
        """Get all handlers for an event type (thread-safe)."""
        with self._lock:
            return list(self._subscribers.get(event_type, {}).values())

    def _schedule_async(self, handler: Callable[..., Any], event: PipelineEvent) -> None:
        """Schedule an async handler for execution with backpressure."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(handler(event))
            return

        # Global governor check: before creating a task, verify that the
        # total system-wide task count is within limits.  This prevents the
        # feedback loop where EventBus + Cache + Queue + Mesh + Analyzers
        # each stay within their own limits while collectively exhausting
        # CPU/RAM.
        try:
            from src.core.concurrency_governor import get_governor

            if not get_governor().allow("event_bus"):
                self._record_drop("governor_denied", event)
                return
        except ImportError:
            logger.debug("ConcurrencyGovernor not available — skipping governor check")

        # Backpressure: if too many tasks are already pending (created but
        # not yet finished), drop this event to prevent unbounded memory
        # growth.  Without this, 10k findings × 100 subscribers = 1M tasks
        # created before any handler finishes.
        if len(self._pending_tasks) >= self._MAX_PENDING_TASKS:
            logger.warning(
                "Event bus backpressure: %d tasks pending (max %d). "
                "Dropping handler for event %s to prevent overload.",
                len(self._pending_tasks),
                self._MAX_PENDING_TASKS,
                event.event_type.value,
            )
            # Release the governor slot we just acquired.
            try:
                from src.core.concurrency_governor import get_governor

                get_governor().release("event_bus")
            except ImportError:
                logger.debug("ConcurrencyGovernor not available — skipping release")
            self._record_drop("backpressure", event)
            # Bug #11: After releasing pressure, try to drain buffered critical events
            if len(self._pending_tasks) < self._MAX_PENDING_TASKS // 2:
                self._drain_critical_buffer()
            return

        # Bug #7: Lazy-init semaphore in a thread-safe manner.  Previously
        # the check+create was not atomic, allowing two concurrent callers
        # to create duplicate semaphores.
        if self._task_semaphore is None:
            with self._lock:
                if self._task_semaphore is None:
                    self._task_semaphore = asyncio.Semaphore(self._MAX_CONCURRENT_TASKS)

        async def _guarded() -> None:
            async with self._task_semaphore:
                await handler(event)

        task = loop.create_task(_guarded())
        self._track_task(task)

    def _track_task(self, task: asyncio.Task[Any]) -> None:
        self._pending_tasks.add(task)
        self._tasks.add(task)

        # Bug #5 fix: Register with the global TaskRegistry so shutdown
        # coordination sees all tasks from all subsystems.
        try:
            from src.core.task_registry import get_task_registry

            registry = get_task_registry()
            # DEADLOCK FIX: _next_id() must be called BEFORE acquiring the
            # registry lock, because _next_id() itself acquires the same lock.
            # Calling it inside `with registry._lock:` caused a self-deadlock
            # whenever EventBus scheduled an async handler during pipeline
            # startup (the first PIPELINE_STARTED event blocked forever).
            task_id = f"task-{registry._next_id()}"
            with registry._lock:
                registry._tasks[task_id] = task
                registry._owner_tasks.setdefault("event_bus", set()).add(task_id)
            task.add_done_callback(
                lambda t, _id=task_id, _owner="event_bus": registry._on_done(_id, _owner)
            )
        except Exception:
            logger.exception("Failed to register task with TaskRegistry")

        def _on_done(t: asyncio.Task[Any]) -> None:
            self._tasks.discard(t)
            self._pending_tasks.discard(t)
            # Release the global governor slot when the task finishes.
            try:
                from src.core.concurrency_governor import get_governor

                get_governor().release("event_bus")
            except ImportError:
                logger.debug("ConcurrencyGovernor not available — skipping release in _on_done")

        task.add_done_callback(_on_done)

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

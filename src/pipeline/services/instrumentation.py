"""Pipeline Stage Instrumentation and Telemetry.

Provides `@instrument` decorator, `StageEvent` telemetry schema, and
publishes telemetry events through the core EventBus.
"""

from __future__ import annotations

import functools
import logging
import time
from collections.abc import Callable
from typing import Any, cast

import msgspec

from src.core.events import EventType, PipelineEvent, get_event_bus

logger = logging.getLogger(__name__)


class StageEvent(msgspec.Struct):
    """Formal stage telemetry payload."""

    stage_name: str
    latency_seconds: float
    memory_footprint_mb: float
    termination_code: int
    details: dict[str, Any] = {}


# Adapter to publish StageEvent through the core EventBus
class _StageEventBus:
    """Adapter that publishes StageEvent through the core EventBus."""

    def __init__(self) -> None:
        self._core_bus = get_event_bus()

    def __call__(self, event: StageEvent) -> None:
        pipeline_event = PipelineEvent(
            event_type=EventType.STAGE_TELEMETRY,
            source=f"instrumentation:{event.stage_name}",
            data={
                "stage_name": event.stage_name,
                "latency_seconds": event.latency_seconds,
                "memory_footprint_mb": event.memory_footprint_mb,
                "termination_code": event.termination_code,
                "details": event.details,
            },
        )
        self._core_bus.publish(pipeline_event)

    def subscribe(self, listener: Callable[[StageEvent], None]) -> None:
        """Subscribe to stage telemetry events."""

        def _handler(event: PipelineEvent) -> None:
            if event.event_type == EventType.STAGE_TELEMETRY:
                stage_event = StageEvent(
                    stage_name=event.data.get("stage_name", ""),
                    latency_seconds=event.data.get("latency_seconds", 0.0),
                    memory_footprint_mb=event.data.get("memory_footprint_mb", 0.0),
                    termination_code=event.data.get("termination_code", 0),
                    details=event.data.get("details", {}),
                )
                listener(stage_event)

        self._core_bus.subscribe(EventType.STAGE_TELEMETRY, _handler)

    def unsubscribe(self, listener: Callable[[StageEvent], None]) -> None:
        """Note: Unsubscription requires tracking subscription IDs."""
        pass  # TODO: Track subscription IDs for proper unsubscribe support


# First-class importable event bus callable
event_bus = _StageEventBus()


def get_memory_usage() -> float:
    """Return the resident set size (RSS) memory usage of the process in MB."""
    try:
        import psutil

        process = psutil.Process()
        return cast(float, process.memory_info().rss / (1024 * 1024))
    except Exception:
        return 0.0


def instrument(func_or_stage_name: Any = None) -> Callable[..., Any]:
    """Decorator to track stage execution latency, memory footprint, and termination codes."""

    def decorator(func: Callable[..., Any], stage_name: str | None = None) -> Callable[..., Any]:
        actual_stage_name = stage_name or func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            start_mem = get_memory_usage()
            termination_code = 0
            details: dict[str, Any] = {}
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                termination_code = getattr(exc, "code", getattr(exc, "exit_code", 1))
                if not isinstance(termination_code, int):
                    termination_code = 1
                details = {"error": str(exc), "error_type": exc.__class__.__name__}
                raise
            finally:
                latency = time.perf_counter() - start_time
                end_mem = get_memory_usage()
                mem_footprint = max(0.0, end_mem - start_mem)
                event = StageEvent(
                    stage_name=actual_stage_name,
                    latency_seconds=latency,
                    memory_footprint_mb=mem_footprint,
                    termination_code=termination_code,
                    details=details,
                )
                event_bus(event)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.perf_counter()
            start_mem = get_memory_usage()
            termination_code = 0
            details: dict[str, Any] = {}
            try:
                return await func(*args, **kwargs)
            except Exception as exc:
                termination_code = getattr(exc, "code", getattr(exc, "exit_code", 1))
                if not isinstance(termination_code, int):
                    termination_code = 1
                details = {"error": str(exc), "error_type": exc.__class__.__name__}
                raise
            finally:
                latency = time.perf_counter() - start_time
                end_mem = get_memory_usage()
                mem_footprint = max(0.0, end_mem - start_mem)
                event = StageEvent(
                    stage_name=actual_stage_name,
                    latency_seconds=latency,
                    memory_footprint_mb=mem_footprint,
                    termination_code=termination_code,
                    details=details,
                )
                event_bus(event)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    if func_or_stage_name is None:
        return lambda f: decorator(f)
    elif callable(func_or_stage_name):
        return decorator(func_or_stage_name)
    else:
        stage_name = str(func_or_stage_name)
        return lambda f: decorator(f, stage_name)

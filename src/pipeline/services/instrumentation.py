"""Pipeline Stage Instrumentation and Telemetry.

Provides `@instrument` decorator, `StageEvent` telemetry schema, and `event_bus` singleton.
"""

from __future__ import annotations

import functools
import logging
import threading
import time
from collections.abc import Callable
from typing import Any, cast

import msgspec

logger = logging.getLogger(__name__)


class StageEvent(msgspec.Struct):
    """Formal stage telemetry payload."""

    stage_name: str
    latency_seconds: float
    memory_footprint_mb: float
    termination_code: int
    details: dict[str, Any] = {}


class EventBus:
    """Thread-safe telemetry event bus."""

    def __init__(self) -> None:
        self._listeners: list[Callable[[StageEvent], None]] = []
        self._lock = threading.Lock()

    def subscribe(self, listener: Callable[[StageEvent], None]) -> None:
        with self._lock:
            if listener not in self._listeners:
                self._listeners.append(listener)

    def unsubscribe(self, listener: Callable[[StageEvent], None]) -> None:
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)

    def emit(self, event: StageEvent) -> None:
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception as exc:
                logger.error("Error in EventBus listener: %s", exc)

    def __call__(self, event: StageEvent) -> None:
        self.emit(event)


# First-class importable event bus callable
event_bus = EventBus()


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

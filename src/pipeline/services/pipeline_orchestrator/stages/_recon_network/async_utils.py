"""Async utilities for recon network stage."""

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _consume_background_task_result(task: asyncio.Task[Any]) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        return
    except Exception as exc:
        logger.debug("Suppressed late result from timed-out sync helper task: %s", exc)


async def _run_sync_with_heartbeat[T](
    sync_call: Callable[[], T],
    *,
    heartbeat_seconds: int,
    on_heartbeat: Any,
    max_duration_seconds: int | None = None,
) -> T:
    task = asyncio.create_task(asyncio.to_thread(sync_call))
    task.add_done_callback(_consume_background_task_result)
    started = time.monotonic()
    while True:
        elapsed = time.monotonic() - started
        timeout_seconds = float(heartbeat_seconds)
        if max_duration_seconds is not None:
            remaining = float(max_duration_seconds) - elapsed
            if remaining <= 0:
                raise TimeoutError(
                    f"Synchronous operation exceeded {max_duration_seconds}s runtime budget"
                )
            timeout_seconds = min(timeout_seconds, remaining)
        done, _pending = await asyncio.wait({task}, timeout=timeout_seconds)
        if task in done:
            if task.cancelled():
                raise TimeoutError("Synchronous operation task was cancelled")
            task_error = task.exception()
            if task_error is not None:
                raise task_error
            return task.result()
        elapsed = time.monotonic() - started
        if max_duration_seconds is not None and elapsed >= float(max_duration_seconds):
            raise TimeoutError(
                f"Synchronous operation exceeded {max_duration_seconds}s runtime budget"
            )
        on_heartbeat(elapsed)

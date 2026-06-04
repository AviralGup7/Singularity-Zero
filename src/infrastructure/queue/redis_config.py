"""Centralized Redis connection configuration.

Historically each Redis-using subsystem defined its own copy of the
timeout/retries/backoff constants, with values drifting between 3s and 5s
timeouts.  This module is the single source of truth — every subsystem
must import its connection knobs from here and not redefine them.

Environment overrides are honored so deployments can tune behavior
without code changes:

* ``REDIS_TIMEOUT_SECONDS``     -> socket_connect / socket_timeout
* ``REDIS_MAX_RETRIES``         -> number of retry attempts after a failure
* ``REDIS_BACKOFF_SECONDS``     -> base delay between retries (doubles)
* ``REDIS_RECONNECT_SECONDS``   -> delay between health-check re-connects

Defaults were chosen to balance responsiveness against transient network
blips in a single-DC deployment.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

T = TypeVar("T")

DEFAULT_TIMEOUT_SECONDS: float = 5.0
DEFAULT_MAX_RETRIES: int = 2
DEFAULT_BACKOFF_SECONDS: float = 0.1
DEFAULT_RECONNECT_SECONDS: float = 30.0


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


REDIS_TIMEOUT_SECONDS: float = _env_float("REDIS_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
REDIS_MAX_RETRIES: int = _env_int("REDIS_MAX_RETRIES", DEFAULT_MAX_RETRIES)
REDIS_BACKOFF_SECONDS: float = _env_float("REDIS_BACKOFF_SECONDS", DEFAULT_BACKOFF_SECONDS)
REDIS_RECONNECT_SECONDS: float = _env_float("REDIS_RECONNECT_SECONDS", DEFAULT_RECONNECT_SECONDS)


def redis_socket_kwargs() -> dict[str, Any]:
    """Return the standard socket timeout kwargs to pass to the Redis client."""
    return {
        "socket_connect_timeout": REDIS_TIMEOUT_SECONDS,
        "socket_timeout": REDIS_TIMEOUT_SECONDS,
    }


def redis_retry_sync[T](operation: Callable[[], T], *, label: str = "redis_op") -> T:
    """Run a synchronous Redis operation with retry+backoff semantics.

    Mirrors the legacy behavior: up to ``REDIS_MAX_RETRIES`` extra attempts
    after the first try, with exponential backoff.  Raises the last
    exception if all attempts fail.
    """
    last_error: Exception | None = None
    delay = REDIS_BACKOFF_SECONDS
    for attempt in range(REDIS_MAX_RETRIES + 1):
        try:
            return operation()
        except Exception as exc:  # noqa: BLE001 - we re-raise the last error
            last_error = exc
            if attempt >= REDIS_MAX_RETRIES:
                break
            time.sleep(delay)
            delay *= 2
    if last_error is not None:
        raise last_error
    raise RuntimeError(f"{label}: exhausted retries with no captured error")


async def redis_retry_async[T](
    operation: Callable[[], Awaitable[T]], *, label: str = "redis_op"
) -> T:
    """Async version of :func:`redis_retry_sync`."""
    last_error: Exception | None = None
    delay = REDIS_BACKOFF_SECONDS
    for attempt in range(REDIS_MAX_RETRIES + 1):
        try:
            return await operation()
        except Exception as exc:  # noqa: BLE001 - we re-raise the last error
            last_error = exc
            if attempt >= REDIS_MAX_RETRIES:
                break
            await asyncio.sleep(delay)
            delay *= 2
    if last_error is not None:
        raise last_error
    raise RuntimeError(f"{label}: exhausted retries with no captured error")


__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_BACKOFF_SECONDS",
    "DEFAULT_RECONNECT_SECONDS",
    "REDIS_TIMEOUT_SECONDS",
    "REDIS_MAX_RETRIES",
    "REDIS_BACKOFF_SECONDS",
    "REDIS_RECONNECT_SECONDS",
    "redis_socket_kwargs",
    "redis_retry_sync",
    "redis_retry_async",
]

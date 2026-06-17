"""Core retry primitives for tool execution.

Provides standalone retry helpers (``retry_ready``, ``sleep_before_retry``)
that depend only on basic Python stdlib and a policy protocol. Used by
recon, pipeline, and execution without cross-layer dependencies.
"""

from __future__ import annotations

import time
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class RetryPolicyProtocol(Protocol):
    """Minimal protocol for retry policy objects."""

    @property
    def max_attempts(self) -> int: ...

    def delay_for_attempt(self, attempt: int) -> float: ...


def retry_ready(policy: Any, attempt: int) -> bool:
    """Return True when another retry attempt is still allowed."""
    return bool(attempt < policy.max_attempts)


def sleep_before_retry(policy: Any, attempt: int) -> float:
    """Sleep for the backoff delay appropriate for the next attempt.

    Returns the delay that was slept.
    """
    delay = float(policy.delay_for_attempt(attempt + 1))
    if delay > 0:
        time.sleep(delay)
    return delay


async def sleep_before_retry_async(policy: Any, attempt: int) -> float:
    """Async version that uses asyncio.sleep instead of blocking time.sleep.

    Returns the delay that was slept.
    """
    import asyncio

    delay = float(policy.delay_for_attempt(attempt + 1))
    if delay > 0:
        await asyncio.sleep(delay)
    return delay

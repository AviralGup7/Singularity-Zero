"""Main job queue implementation with priority scheduling and state management.

Provides the core JobQueue class with job enqueue/dequeue, priority-based
scheduling, atomic state transitions via Redis Lua scripts, lease management,
dead-letter queue handling, and configurable retry policies.

This module is now a backward-compatibility shim. The implementation lives
in sibling modules in this package:

- :mod:`src.infrastructure.queue.core` - core initialization, key helpers,
  Lua-script registration, and enqueue/handler management.
- :mod:`src.infrastructure.queue.persistence` - job retrieval, dead-letter
  operations, cancellation, metrics, and health/self-healing helpers.
- :mod:`src.infrastructure.queue.consumer_groups` - claim, complete, fail,
  release, and worker listing/registration.
- :mod:`src.infrastructure.queue.rate_limiter` - stale-lease cleanup and
  rate-limit / scheduler-aware claim fallback.

Importing this module is therefore equivalent to importing
``JobQueue`` from ``src.infrastructure.queue``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from src.infrastructure.queue.retry_policy import RetryPolicy

from src.infrastructure.queue.consumer_groups import (
    JobQueueConsumerGroupsMixin as _JobQueueConsumerGroups,
)
from src.infrastructure.queue.core import JobQueueCore
from src.infrastructure.queue.persistence import (
    JobQueuePersistenceMixin as _JobQueuePersistence,
)
from src.infrastructure.queue.rate_limiter import (
    JobQueueRateLimiterMixin as _JobQueueRateLimiter,
)


class JobQueue(
    _JobQueuePersistence,
    _JobQueueConsumerGroups,
    _JobQueueRateLimiter,
    JobQueueCore,
):
    """Production-grade distributed job queue with Redis backend.

    Provides atomic job operations, priority scheduling, lease-based job
    claiming, configurable retry policies, and dead-letter queue handling.

    The queue uses Redis sorted sets for priority ordering and Lua scripts
    for atomic state transitions. An in-memory fallback is used when Redis
    is unavailable.

    Attributes:
        config: Queue configuration instance.
        redis: Redis client wrapper instance.
        retry_policy: Retry policy for failed jobs.
        _handlers: Dict mapping job types to handler functions.
        _scripts: Registered Lua script SHAs.
    """

"""Abstract base class for queue workers.

Provides a common interface for both the full Worker and LiteWorker,
enabling transparent substitution and shared dispatch logic.
"""
from __future__ import annotations

import abc
import asyncio
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger
from src.infrastructure.queue.models import Job

logger = get_pipeline_logger(__name__)


class BaseWorker(abc.ABC):
    """Abstract base class defining the worker contract.

    Both ``Worker`` (full) and ``LiteWorker`` must implement these
    methods so that the queue system can treat them uniformly.
    """

    worker_id: str
    queue_name: str
    concurrency: int
    capabilities: list[str]
    _running: bool

    @abc.abstractmethod
    async def start(self) -> None:
        """Start the worker event loop."""
        ...

    @abc.abstractmethod
    async def stop(self) -> None:
        """Initiate graceful shutdown."""
        ...

    @abc.abstractmethod
    async def _register(self) -> None:
        """Register the worker in Redis."""
        ...

    @abc.abstractmethod
    async def _heartbeat(self) -> None:
        """Send periodic heartbeat signals."""
        ...

    @abc.abstractmethod
    async def _poll_and_process(self) -> None:
        """Poll for jobs and dispatch them."""
        ...

    @abc.abstractmethod
    async def _process_job(self, job_id: str, job_type: str, payload: dict[str, Any]) -> None:
        """Process a single claimed job."""
        ...

    @abc.abstractmethod
    async def _cleanup(self) -> None:
        """Release leases and deregister."""
        ...

    @property
    def is_running(self) -> bool:
        """Whether the worker is currently processing."""
        return self._running

    def can_handle(self, job_type: str) -> bool:
        """Return True if this worker can handle the given job type.

        Override in subclasses to advertise supported types.
        """
        return True

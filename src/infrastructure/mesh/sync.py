"""
Cyber Security Test Pipeline - Neural-Mesh Synchronization Utility.
Provides generic Redis Pub/Sub capabilities for cross-node state synchronization.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from typing import Any

import redis.asyncio as redis

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MeshSyncSnapshot:
    """Observable Redis mesh-sync counters for API consumers."""

    channel: str
    channel_scoped: str
    running: bool
    messages_published_total: int
    messages_received_total: int
    publish_failures_total: int
    listen_failures_total: int
    last_error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class MeshSync:
    """
    Redis Pub/Sub synchronization client.
    Enables nodes to broadcast and receive state updates (e.g., FP patterns,
    mesh-wide config changes).
    """

    def __init__(self, redis_url: str, channel: str):
        self.redis_url = redis_url
        self.channel = channel
        self._client = redis.from_url(redis_url, decode_responses=True)
        self._pubsub = self._client.pubsub()
        self._running = False
        self._task: asyncio.Task[Any] | None = None
        self._messages_published_total = 0
        self._messages_received_total = 0
        self._publish_failures_total = 0
        self._listen_failures_total = 0
        self._last_error = ""

    @property
    def channel_scoped(self) -> str:
        from src.core.tenant_context import TenantContext

        tenant_id = TenantContext.get_current_tenant()
        if tenant_id:
            return f"{tenant_id}:{self.channel}"
        return self.channel

    async def publish(self, message: dict[str, Any]) -> None:
        """Broadcast a message to the mesh."""
        try:
            await self._client.publish(self.channel_scoped, json.dumps(message))
            self._messages_published_total += 1
            _inc_metric(
                "mesh_sync_messages_published_total",
                "Total Redis mesh sync messages published",
            )
        except Exception as e:
            self._publish_failures_total += 1
            self._last_error = str(e)
            _inc_metric(
                "mesh_sync_publish_failures_total",
                "Total Redis mesh sync publish failures",
            )
            logger.debug("MeshSync: Failed to publish message on %s: %s", self.channel_scoped, e)

    async def start_listening(self, callback: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        """Start a background loop to listen for messages and invoke the callback."""
        if self._running:
            return

        self._running = True
        await self._pubsub.subscribe(self.channel_scoped)
        self._task = asyncio.create_task(
            self._listen_loop(callback), name=f"mesh-sync-listener-{self.channel_scoped}"
        )
        logger.info("MeshSync: Subscribed to channel '%s'", self.channel_scoped)

    async def _listen_loop(self, callback: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        """Internal listen loop."""
        while self._running:
            try:
                # get_message with timeout to avoid blocking forever and allow shutdown
                message = await self._pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if message and message["type"] == "message":
                    data = json.loads(message["data"])
                    self._messages_received_total += 1
                    _inc_metric(
                        "mesh_sync_messages_received_total",
                        "Total Redis mesh sync messages received",
                    )
                    await callback(data)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._listen_failures_total += 1
                self._last_error = str(e)
                _inc_metric(
                    "mesh_sync_listen_failures_total",
                    "Total Redis mesh sync listen failures",
                )
                logger.debug("MeshSync: Listen loop error on %s: %s", self.channel_scoped, e)
                await asyncio.sleep(1.0)

    def health_snapshot(self) -> dict[str, Any]:
        """Return mesh sync telemetry without requiring dashboard coupling."""
        snapshot = MeshSyncSnapshot(
            channel=self.channel,
            channel_scoped=self.channel_scoped,
            running=self._running,
            messages_published_total=self._messages_published_total,
            messages_received_total=self._messages_received_total,
            publish_failures_total=self._publish_failures_total,
            listen_failures_total=self._listen_failures_total,
            last_error=self._last_error,
        )
        _set_metric(
            "mesh_sync_publish_failures",
            snapshot.publish_failures_total,
            "Current Redis mesh sync publish failures",
        )
        _set_metric(
            "mesh_sync_listen_failures",
            snapshot.listen_failures_total,
            "Current Redis mesh sync listen failures",
        )
        return snapshot.as_dict()

    async def stop(self) -> None:
        """Stop listening and close the Redis connection."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        try:
            await self._pubsub.unsubscribe(self.channel_scoped)
            await self._client.close()
            logger.info("MeshSync: Disconnected from channel '%s'", self.channel_scoped)
        except Exception as e:
            logger.debug("MeshSync: Shutdown error: %s", e)


def _inc_metric(name: str, description: str) -> None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        get_metrics().counter(name, description).inc()
    except Exception:
        logger.debug("MeshSync metric increment skipped for %s", name, exc_info=True)


def _set_metric(name: str, value: float | int | bool, description: str) -> None:
    try:
        from src.infrastructure.observability.metrics import get_metrics

        get_metrics().gauge(name, description).set(float(value))
    except Exception:
        logger.debug("MeshSync metric gauge skipped for %s", name, exc_info=True)

"""
Cyber Security Test Pipeline - Neural-Mesh Synchronization Utility.
Provides generic Redis Pub/Sub capabilities for cross-node state synchronization.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

import redis.asyncio as redis

logger = logging.getLogger(__name__)


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

    async def publish(self, message: dict[str, Any]) -> None:
        """Broadcast a message to the mesh."""
        try:
            await self._client.publish(self.channel, json.dumps(message))
        except Exception as e:
            logger.debug("MeshSync: Failed to publish message on %s: %s", self.channel, e)

    async def start_listening(self, callback: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        """Start a background loop to listen for messages and invoke the callback."""
        if self._running:
            return

        self._running = True
        await self._pubsub.subscribe(self.channel)
        self._task = asyncio.create_task(
            self._listen_loop(callback),
            name=f"mesh-sync-listener-{self.channel}"
        )
        logger.info("MeshSync: Subscribed to channel '%s'", self.channel)

    async def _listen_loop(self, callback: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
        """Internal listen loop."""
        while self._running:
            try:
                # get_message with timeout to avoid blocking forever and allow shutdown
                message = await self._pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    data = json.loads(message["data"])
                    await callback(data)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("MeshSync: Listen loop error on %s: %s", self.channel, e)
                await asyncio.sleep(1.0)

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
            await self._pubsub.unsubscribe(self.channel)
            await self._client.close()
            logger.info("MeshSync: Disconnected from channel '%s'", self.channel)
        except Exception as e:
            logger.debug("MeshSync: Shutdown error: %s", e)

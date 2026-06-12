"""
Integration tests for the MeshSync Redis synchronization utility.
"""

import asyncio
from typing import Any

import pytest

from src.infrastructure.mesh.sync import MeshSync


class MockAsyncPubSub:
    """Mock for the redis.asyncio PubSub object."""

    def __init__(self) -> None:
        self.subscribed_channels: set[str] = set()
        self.queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

    async def subscribe(self, channel: str) -> None:
        self.subscribed_channels.add(channel)

    async def unsubscribe(self, channel: str) -> None:
        self.subscribed_channels.discard(channel)

    async def get_message(
        self, ignore_subscribe_messages: bool = True, timeout: float = 1.0
    ) -> dict[str, Any] | None:
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except TimeoutError:
            return None


class MockAsyncRedisClient:
    """Mock for the redis.asyncio Redis client."""

    def __init__(self) -> None:
        self._pubsub = MockAsyncPubSub()
        self.published_messages: list[tuple[str, str]] = []

    def pubsub(self) -> MockAsyncPubSub:
        return self._pubsub

    async def publish(self, channel: str, message_str: str) -> None:
        self.published_messages.append((channel, message_str))
        if channel in self._pubsub.subscribed_channels:
            msg = {"type": "message", "channel": channel, "data": message_str}
            await self._pubsub.queue.put(msg)

    async def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_mesh_sync_pubsub_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that MeshSync correctly publishes and listens for channel events."""
    # 1. Setup mock redis and patch from_url
    mock_redis = MockAsyncRedisClient()
    monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: mock_redis)

    # 2. Instantiate MeshSync
    channel_name = "test-mesh-sync-channel"
    sync_client = MeshSync(redis_url="redis://localhost", channel=channel_name)

    # 3. Define callback and test receiving a message
    received_messages: list[dict[str, Any]] = []

    async def message_callback(msg: dict[str, Any]) -> None:
        received_messages.append(msg)

    # Start listening
    await sync_client.start_listening(message_callback)

    # Publish a message through the client
    test_msg = {"event": "node_joined", "node_id": "node-999"}
    await sync_client.publish(test_msg)

    # Give the listener loop a moment to consume from queue
    await asyncio.sleep(0.1)

    # Verify callback was called
    assert len(received_messages) == 1
    assert received_messages[0] == test_msg

    # Verify message was also tracked as published on mock
    assert len(mock_redis.published_messages) == 1
    published_channel = mock_redis.published_messages[0][0]
    assert published_channel.endswith(channel_name)

    # Stop the sync client
    await sync_client.stop()

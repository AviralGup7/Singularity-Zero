import asyncio

import pytest

from src.core.frontier.ring_bus import FrontierRingBus, NeuralEvent


@pytest.mark.asyncio
async def test_ring_bus_subscribe_emit():
    bus = FrontierRingBus(capacity=10)
    received = []
    event_received = asyncio.Event()

    def handler(event: NeuralEvent):
        received.append(event)
        event_received.set()

    bus.subscribe("test_event", handler)

    task = asyncio.create_task(bus.start_dispatch_loop())
    bus.emit("test_event", "test_source", {"data": 1})

    try:
        await asyncio.wait_for(event_received.wait(), timeout=2.0)
    except TimeoutError:
        pytest.fail("Test event was not received within timeout")

    assert len(received) == 1
    assert received[0].type == "test_event"
    assert received[0].source == "test_source"

    bus.stop()
    await task


@pytest.mark.asyncio
async def test_ring_bus_preserves_multiple_large_payloads_with_shm_enabled():
    bus = FrontierRingBus(capacity=10, enable_shm=True)
    received = []
    all_received = asyncio.Event()

    async def handler(event: NeuralEvent):
        received.append(event.data)
        if len(received) == 2:
            all_received.set()

    bus.subscribe("large_event", handler)

    first = {"payload": "a" * 2048}
    second = {"payload": "b" * 2048}
    bus.emit("large_event", "test_source", first)
    bus.emit("large_event", "test_source", second)

    task = asyncio.create_task(bus.start_dispatch_loop())
    try:
        await asyncio.wait_for(all_received.wait(), timeout=2.0)
    except TimeoutError:
        pytest.fail("Large events were not received within timeout")
    finally:
        bus.stop()
        await task

    assert received == [first, second]

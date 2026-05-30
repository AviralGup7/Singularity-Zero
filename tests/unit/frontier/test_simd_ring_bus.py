"""Tests for AVX-512 SIMD msgpack Zero-Copy Ring Bus Router."""

import asyncio
import pytest
from src.core.frontier.ring_bus import FrontierRingBus, NeuralEvent
from src.core.frontier.shared_memory import ZeroCopyRouter

@pytest.mark.asyncio
async def test_ring_bus_shm_zero_copy():
    # Initialize bus with SHM enabled
    bus = FrontierRingBus(capacity=100, enable_shm=True)
    
    # Large payload to trigger SHM offload (> 1KB)
    large_data = {"key": "x" * 2000}
    
    received_event = None
    async def handler(event):
        nonlocal received_event
        received_event = event

    bus.subscribe("test_event", handler)
    
    # Emit event
    bus.emit("test_event", "source", large_data)
    
    # Start dispatch loop briefly
    dispatch_task = asyncio.create_task(bus.start_dispatch_loop())
    
    # Wait for processing
    for _ in range(10):
        if received_event:
            break
        await asyncio.sleep(0.1)
    
    bus.stop()
    await dispatch_task
    
    assert received_event is not None
    assert received_event.data == large_data
    assert received_event.shm_ref is not None
    assert received_event.shm_ref.startswith("shm://")

def test_zero_copy_router_basic():
    router = ZeroCopyRouter(buffer_name="test_buffer", buffer_size=1024)
    payload = b"hello world SIMD"
    
    location = router.route_payload(payload)
    assert location == "shm://test_buffer@0"
    
    retrieved = router.retrieve_payload(location)
    assert retrieved == payload

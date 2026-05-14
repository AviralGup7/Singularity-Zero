import pytest
import asyncio
from src.core.frontier.ring_bus import FrontierRingBus, NeuralEvent

@pytest.mark.asyncio
async def test_ring_bus_subscribe_emit():
    bus = FrontierRingBus(capacity=10)
    received = []
    
    def handler(event: NeuralEvent):
        received.append(event)
        
    bus.subscribe("test_event", handler)
    
    task = asyncio.create_task(bus.start_dispatch_loop())
    bus.emit("test_event", "test_source", {"data": 1})
    
    await asyncio.sleep(0.1)
    
    assert len(received) == 1
    assert received[0].type == "test_event"
    assert received[0].source == "test_source"
    
    bus.stop()
    await task

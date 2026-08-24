import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock

from src.websocket_server.broadcaster import Broadcaster
from src.websocket_server.manager import ConnectionInfo, ConnectionManager
from src.websocket_server.protocol import BaseMessage, MessageType



class MockWebSocket:
    def __init__(self):
        self.state = 1
        self.client_state = 1
        self.send_text = AsyncMock()


class TestLossyVsCriticalBackpressure(unittest.IsolatedAsyncioTestCase):
    async def test_critical_events_preserved_under_backpressure(self):
        manager = ConnectionManager()
        broadcaster = Broadcaster(manager, enable_redis=False)

        ws = MockWebSocket()
        info = await manager.connect(
            websocket=ws,  # type: ignore[arg-type]
            user_id="user_1",
            connection_id="conn_1",
            client_ip="127.0.0.1",
        )
        assert info is not None
        info._message_queue = asyncio.Queue(maxsize=3)

        # 1. Fill queue with 3 lossy telemetry/progress messages
        m1 = BaseMessage(type=MessageType.TELEMETRY, id="m1")
        m2 = BaseMessage(type=MessageType.PROGRESS, id="m2")
        m3 = BaseMessage(type=MessageType.TELEMETRY, id="m3")

        await broadcaster._enqueue(info, m1)
        await broadcaster._enqueue(info, m2)
        await broadcaster._enqueue(info, m3)
        self.assertEqual(info.message_queue.qsize(), 3)

        # 2. Enqueue a critical finding alert message when queue is full
        crit_json = json.dumps({"type": "finding", "event": "finding_alert", "id": "f_1", "title": "SQLi"})

        # Call backpressure directly with critical payload
        await broadcaster._handle_backpressure(info, crit_json)

        # Queue should still have items, and the critical item MUST be in the queue
        items = []
        while not info.message_queue.empty():
            items.append(info.message_queue.get_nowait())

        self.assertIn(crit_json, items)

    async def test_lossy_metrics_dropped_when_queue_full_of_critical_events(self):
        manager = ConnectionManager()
        broadcaster = Broadcaster(manager, enable_redis=False)

        ws = MockWebSocket()
        info = await manager.connect(
            websocket=ws,  # type: ignore[arg-type]
            user_id="user_2",
            connection_id="conn_2",
            client_ip="127.0.0.1",
        )
        assert info is not None
        info._message_queue = asyncio.Queue(maxsize=2)


        # 1. Fill queue with 2 critical messages
        c1 = json.dumps({"type": "finding", "id": "f1", "title": "Critical RCE"})
        c2 = json.dumps({"type": "status", "id": "s1", "event": "stage_completed"})
        info.message_queue.put_nowait(c1)
        info.message_queue.put_nowait(c2)

        # 2. A lossy metric arrives when queue is full
        metric_msg = json.dumps({"type": "telemetry", "cpu": 80.5, "fps": 60})
        await broadcaster._handle_backpressure(info, metric_msg)

        # The queue must still retain the 2 critical messages and drop the metric
        items = []
        while not info.message_queue.empty():
            items.append(info.message_queue.get_nowait())

        self.assertEqual(len(items), 2)
        self.assertIn(c1, items)
        self.assertIn(c2, items)
        self.assertNotIn(metric_msg, items)

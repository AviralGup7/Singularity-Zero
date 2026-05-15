"""Unit tests for core.events module."""

import threading
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.core.events import EventBus, EventType, PipelineEvent


@pytest.mark.unit
class TestEventBusSubscribe(unittest.TestCase):
    def setUp(self) -> None:
        self.bus = EventBus()

    def test_subscribe_returns_unique_id(self) -> None:
        handler = MagicMock()
        sub_id_1 = self.bus.subscribe(EventType.STAGE_STARTED, handler)
        sub_id_2 = self.bus.subscribe(EventType.STAGE_STARTED, handler)
        self.assertIsInstance(sub_id_1, str)
        self.assertIsInstance(sub_id_2, str)
        self.assertNotEqual(sub_id_1, sub_id_2)

    def test_subscribe_different_handlers(self) -> None:
        h1 = MagicMock()
        h2 = MagicMock()
        id1 = self.bus.subscribe(EventType.STAGE_STARTED, h1)
        id2 = self.bus.subscribe(EventType.STAGE_STARTED, h2)
        self.assertNotEqual(id1, id2)

    def test_subscribe_same_handler_multiple_events(self) -> None:
        handler = MagicMock()
        id1 = self.bus.subscribe(EventType.STAGE_STARTED, handler)
        id2 = self.bus.subscribe(EventType.STAGE_COMPLETED, handler)
        self.assertNotEqual(id1, id2)

    def test_subscribe_async_returns_unique_id(self) -> None:
        async def async_handler(event: PipelineEvent) -> None:
            pass

        id1 = self.bus.subscribe_async(EventType.STAGE_STARTED, async_handler)
        id2 = self.bus.subscribe_async(EventType.STAGE_STARTED, async_handler)
        self.assertNotEqual(id1, id2)


@pytest.mark.unit
class TestEventBusUnsubscribe(unittest.TestCase):
    def setUp(self) -> None:
        self.bus = EventBus()

    def test_unsubscribe_removes_handler(self) -> None:
        handler = MagicMock()
        sub_id = self.bus.subscribe(EventType.STAGE_STARTED, handler)
        self.bus.unsubscribe(sub_id)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)
        handler.assert_not_called()

    def test_unsubscribe_nonexistent_id_logs_warning(self) -> None:
        with patch("src.core.events.logger") as mock_logger:
            self.bus.unsubscribe("nonexistent-id")
            mock_logger.warning.assert_called_once()

    def test_unsubscribe_only_removes_target(self) -> None:
        h1 = MagicMock()
        h2 = MagicMock()
        id1 = self.bus.subscribe(EventType.STAGE_STARTED, h1)
        self.bus.subscribe(EventType.STAGE_STARTED, h2)
        self.bus.unsubscribe(id1)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)
        h1.assert_not_called()
        h2.assert_called_once_with(event)

    def test_unsubscribe_from_correct_event_type(self) -> None:
        handler = MagicMock()
        sub_id = self.bus.subscribe(EventType.STAGE_STARTED, handler)
        self.bus.unsubscribe(sub_id)
        event = PipelineEvent(event_type=EventType.STAGE_COMPLETED, source="test")
        self.bus.publish(event)
        handler.assert_not_called()


@pytest.mark.unit
class TestEventBusPublish(unittest.TestCase):
    def setUp(self) -> None:
        self.bus = EventBus()

    def test_publish_calls_sync_handler(self) -> None:
        handler = MagicMock()
        self.bus.subscribe(EventType.STAGE_STARTED, handler)
        event = PipelineEvent(
            event_type=EventType.STAGE_STARTED, source="test", data={"key": "value"}
        )
        self.bus.publish(event)
        handler.assert_called_once_with(event)

    def test_publish_calls_multiple_handlers(self) -> None:
        h1 = MagicMock()
        h2 = MagicMock()
        self.bus.subscribe(EventType.STAGE_STARTED, h1)
        self.bus.subscribe(EventType.STAGE_STARTED, h2)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)
        h1.assert_called_once_with(event)
        h2.assert_called_once_with(event)

    def test_publish_no_handlers_does_not_raise(self) -> None:
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)

    def test_publish_only_calls_handlers_for_event_type(self) -> None:
        h1 = MagicMock()
        h2 = MagicMock()
        self.bus.subscribe(EventType.STAGE_STARTED, h1)
        self.bus.subscribe(EventType.STAGE_COMPLETED, h2)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)
        h1.assert_called_once()
        h2.assert_not_called()

    def test_publish_async_handler_schedules_task(self) -> None:
        async def async_handler(event: PipelineEvent) -> None:
            pass

        self.bus.subscribe_async(EventType.STAGE_STARTED, async_handler)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        with patch.object(self.bus, "_schedule_async") as mock_schedule:
            self.bus.publish(event)
            mock_schedule.assert_called_once()

    def test_publish_error_in_handler_does_not_stop_others(self) -> None:
        def bad_handler(event: PipelineEvent) -> None:
            raise ValueError("handler error")

        good_handler = MagicMock()
        self.bus.subscribe(EventType.STAGE_STARTED, bad_handler)
        self.bus.subscribe(EventType.STAGE_STARTED, good_handler)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)
        good_handler.assert_called_once_with(event)

    def test_publish_event_ordering(self) -> None:
        call_order: list[int] = []

        def handler1(event: PipelineEvent) -> None:
            call_order.append(1)

        def handler2(event: PipelineEvent) -> None:
            call_order.append(2)

        def handler3(event: PipelineEvent) -> None:
            call_order.append(3)

        self.bus.subscribe(EventType.STAGE_STARTED, handler1)
        self.bus.subscribe(EventType.STAGE_STARTED, handler2)
        self.bus.subscribe(EventType.STAGE_STARTED, handler3)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)
        self.assertEqual(call_order, [1, 2, 3])


@pytest.mark.unit
class TestEventBusPublishSync(unittest.TestCase):
    def setUp(self) -> None:
        self.bus = EventBus()

    def test_publish_sync_returns_handler_results(self) -> None:
        def handler(event: PipelineEvent) -> str:
            return "result"

        self.bus.subscribe(EventType.STAGE_STARTED, handler)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        results = self.bus.publish_sync(event)
        self.assertEqual(results, ["result"])

    def test_publish_sync_returns_multiple_results(self) -> None:
        def h1(event: PipelineEvent) -> int:
            return 1

        def h2(event: PipelineEvent) -> str:
            return "two"

        self.bus.subscribe(EventType.STAGE_STARTED, h1)
        self.bus.subscribe(EventType.STAGE_STARTED, h2)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        results = self.bus.publish_sync(event)
        self.assertEqual(results, [1, "two"])

    def test_publish_sync_error_returns_none(self) -> None:
        def bad_handler(event: PipelineEvent) -> str:
            raise RuntimeError("fail")

        def good_handler(event: PipelineEvent) -> str:
            return "ok"

        self.bus.subscribe(EventType.STAGE_STARTED, bad_handler)
        self.bus.subscribe(EventType.STAGE_STARTED, good_handler)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        results = self.bus.publish_sync(event)
        self.assertEqual(results, [None, "ok"])

    def test_publish_sync_no_handlers_returns_empty_list(self) -> None:
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        results = self.bus.publish_sync(event)
        self.assertEqual(results, [])

    def test_publish_sync_runs_async_handler(self) -> None:
        async def async_handler(event: PipelineEvent) -> str:
            return "async_result"

        self.bus.subscribe_async(EventType.STAGE_STARTED, async_handler)
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        results = self.bus.publish_sync(event)
        self.assertEqual(results, ["async_result"])


@pytest.mark.unit
class TestEventBusGetHandlers(unittest.TestCase):
    def setUp(self) -> None:
        self.bus = EventBus()

    def test_get_handlers_returns_list(self) -> None:
        handler = MagicMock()
        self.bus.subscribe(EventType.STAGE_STARTED, handler)
        handlers = self.bus._get_handlers(EventType.STAGE_STARTED)
        self.assertIsInstance(handlers, list)
        self.assertEqual(len(handlers), 1)
        self.assertIn(handler, handlers)

    def test_get_handlers_empty_returns_empty_list(self) -> None:
        handlers = self.bus._get_handlers(EventType.STAGE_STARTED)
        self.assertEqual(handlers, [])

    def test_get_handlers_returns_copy(self) -> None:
        handler = MagicMock()
        self.bus.subscribe(EventType.STAGE_STARTED, handler)
        handlers1 = self.bus._get_handlers(EventType.STAGE_STARTED)
        handlers1.clear()
        handlers2 = self.bus._get_handlers(EventType.STAGE_STARTED)
        self.assertEqual(len(handlers2), 1)


@pytest.mark.unit
class TestEventBusClear(unittest.TestCase):
    def setUp(self) -> None:
        self.bus = EventBus()

    def test_clear_removes_all_subscriptions(self) -> None:
        h1 = MagicMock()
        h2 = MagicMock()
        self.bus.subscribe(EventType.STAGE_STARTED, h1)
        self.bus.subscribe(EventType.STAGE_COMPLETED, h2)
        self.bus.clear()
        event = PipelineEvent(event_type=EventType.STAGE_STARTED, source="test")
        self.bus.publish(event)
        h1.assert_not_called()

    def test_clear_removes_async_handlers(self) -> None:
        async def async_handler(event: PipelineEvent) -> None:
            pass

        self.bus.subscribe_async(EventType.STAGE_STARTED, async_handler)
        self.bus.clear()
        self.assertEqual(len(self.bus._async_handlers), 0)


@pytest.mark.unit
class TestEventBusThreadSafety(unittest.TestCase):
    def test_concurrent_subscribe_unsubscribe(self) -> None:
        bus = EventBus()
        errors: list[Exception] = []

        def subscribe_worker() -> None:
            try:
                for _ in range(50):
                    handler = MagicMock()
                    bus.subscribe(EventType.STAGE_STARTED, handler)
            except Exception as e:
                errors.append(e)

        def unsubscribe_worker() -> None:
            try:
                for _ in range(50):
                    handler = MagicMock()
                    sub_id = bus.subscribe(EventType.STAGE_STARTED, handler)
                    bus.unsubscribe(sub_id)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=subscribe_worker),
            threading.Thread(target=unsubscribe_worker),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


@pytest.mark.unit
class TestPipelineEvent(unittest.TestCase):
    def test_event_default_timestamp(self) -> None:
        event = PipelineEvent(event_type=EventType.STAGE_STARTED)
        self.assertIsInstance(event.timestamp, datetime)
        self.assertIsNotNone(event.timestamp.tzinfo)

    def test_event_default_correlation_id(self) -> None:
        event1 = PipelineEvent(event_type=EventType.STAGE_STARTED)
        event2 = PipelineEvent(event_type=EventType.STAGE_STARTED)
        self.assertNotEqual(event1.correlation_id, event2.correlation_id)

    def test_event_default_data_is_empty_dict(self) -> None:
        event = PipelineEvent(event_type=EventType.STAGE_STARTED)
        self.assertEqual(event.data, {})

    def test_event_with_custom_data(self) -> None:
        event = PipelineEvent(
            event_type=EventType.STAGE_COMPLETED,
            source="scanner",
            data={"findings": 5},
        )
        self.assertEqual(event.source, "scanner")
        self.assertEqual(event.data, {"findings": 5})


if __name__ == "__main__":
    unittest.main()

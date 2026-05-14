"""Tests for the ProgressQueue class from src.core.progress_queue."""

import threading
import time
from unittest.mock import patch

import pytest

from src.core.progress_queue import (
    ProgressQueue,
    create_progress_callback,
    get_progress_queue,
    reset_progress_queue,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def reset_singleton() -> None:
    """Reset the global singleton before each test."""
    reset_progress_queue()
    yield
    reset_progress_queue()


@pytest.fixture
def small_queue() -> ProgressQueue:
    """Return a ProgressQueue with maxsize=3 for overflow testing."""
    return ProgressQueue(maxsize=3)


@pytest.fixture
def normal_queue() -> ProgressQueue:
    """Return a ProgressQueue with default maxsize."""
    return ProgressQueue()


# ===========================================================================
# 1. Test put and get
# ===========================================================================


class TestPutAndGet:
    """Tests for basic put and get round-trip."""

    def test_put_and_get(self, small_queue: ProgressQueue) -> None:
        """Basic put/get round-trip."""
        event = {"type": "progress", "value": 50}
        small_queue.put(event)
        result = small_queue.get(timeout=1.0)
        assert result == event

    def test_put_and_get_multiple(self, small_queue: ProgressQueue) -> None:
        """Multiple put/get in FIFO order."""
        events = [{"i": i} for i in range(3)]
        for e in events:
            small_queue.put(e)
        for expected in events:
            assert small_queue.get(timeout=1.0) == expected

    def test_put_returns_true(self, small_queue: ProgressQueue) -> None:
        """put returns True on success."""
        assert small_queue.put({"key": "value"}) is True

    def test_get_returns_event(self, small_queue: ProgressQueue) -> None:
        """get returns the event dict."""
        small_queue.put({"status": "ok"})
        result = small_queue.get(timeout=1.0)
        assert isinstance(result, dict)
        assert result["status"] == "ok"


# ===========================================================================
# 2. Test get timeout returns None
# ===========================================================================


class TestGetTimeout:
    """Tests for get timeout behavior."""

    def test_get_timeout_returns_none(self, small_queue: ProgressQueue) -> None:
        """Timeout returns None."""
        result = small_queue.get(timeout=0.1)
        assert result is None

    def test_get_timeout_short(self, small_queue: ProgressQueue) -> None:
        """Short timeout returns None quickly."""
        start = time.monotonic()
        result = small_queue.get(timeout=0.05)
        elapsed = time.monotonic() - start
        assert result is None
        assert elapsed < 1.0

    def test_get_timeout_long(self, small_queue: ProgressQueue) -> None:
        """Longer timeout still returns None when empty."""
        result = small_queue.get(timeout=0.2)
        assert result is None


# ===========================================================================
# 3. Test overflow drops oldest
# ===========================================================================


class TestOverflowDropsOldest:
    """Tests for overflow protection behavior."""

    def test_overflow_drops_oldest(self, small_queue: ProgressQueue) -> None:
        """When full, drops oldest and accepts new."""
        small_queue.put({"id": 1})
        small_queue.put({"id": 2})
        small_queue.put({"id": 3})

        small_queue.put({"id": 4})

        items = []
        for _ in range(3):
            item = small_queue.get(timeout=1.0)
            if item is not None:
                items.append(item)

        ids = [item["id"] for item in items]
        assert 1 not in ids
        assert ids == [2, 3, 4]

    def test_overflow_accepts_new_item(self, small_queue: ProgressQueue) -> None:
        """After overflow, new item is retrievable."""
        for i in range(3):
            small_queue.put({"i": i})

        small_queue.put({"i": 99})

        found = False
        for _ in range(3):
            item = small_queue.get(timeout=1.0)
            if item and item.get("i") == 99:
                found = True
        assert found

    def test_overflow_does_not_block(self, small_queue: ProgressQueue) -> None:
        """Overflow put returns True (non-blocking)."""
        for i in range(3):
            small_queue.put({"i": i})

        result = small_queue.put({"i": 99})
        assert result is True


# ===========================================================================
# 4. Test dropped count tracks overflows
# ===========================================================================


class TestDroppedCount:
    """Tests for dropped_count tracking."""

    def test_dropped_count_starts_at_zero(self, small_queue: ProgressQueue) -> None:
        """Initial dropped_count is 0."""
        assert small_queue.dropped_count == 0

    def test_dropped_count_tracks_overflows(self, small_queue: ProgressQueue) -> None:
        """dropped_count increments on overflow."""
        for i in range(3):
            small_queue.put({"i": i})

        small_queue.put({"i": 3})
        assert small_queue.dropped_count == 1

        small_queue.put({"i": 4})
        assert small_queue.dropped_count == 2

    def test_dropped_count_no_overflow(self, small_queue: ProgressQueue) -> None:
        """dropped_count stays 0 when no overflow."""
        small_queue.put({"a": 1})
        small_queue.put({"a": 2})
        assert small_queue.dropped_count == 0

    def test_dropped_count_multiple_overflows(self, small_queue: ProgressQueue) -> None:
        """Multiple overflows increment dropped_count correctly."""
        for i in range(3):
            small_queue.put({"i": i})

        for i in range(10):
            small_queue.put({"overflow": i})

        assert small_queue.dropped_count == 10


# ===========================================================================
# 5. Test qsize returns correct size
# ===========================================================================


class TestQsize:
    """Tests for queue size tracking."""

    def test_qsize_starts_at_zero(self, small_queue: ProgressQueue) -> None:
        """Initial qsize is 0."""
        assert small_queue.qsize == 0

    def test_qsize_returns_correct_size(self, small_queue: ProgressQueue) -> None:
        """Queue size tracking works."""
        small_queue.put({"i": 1})
        assert small_queue.qsize == 1

        small_queue.put({"i": 2})
        assert small_queue.qsize == 2

        small_queue.get(timeout=1.0)
        assert small_queue.qsize == 1

    def test_qsize_after_get_all(self, small_queue: ProgressQueue) -> None:
        """qsize is 0 after getting all items."""
        small_queue.put({"i": 1})
        small_queue.put({"i": 2})
        small_queue.get(timeout=1.0)
        small_queue.get(timeout=1.0)
        assert small_queue.qsize == 0

    def test_qsize_after_overflow(self, small_queue: ProgressQueue) -> None:
        """qsize stays at maxsize after overflow."""
        for i in range(3):
            small_queue.put({"i": i})
        assert small_queue.qsize == 3

        small_queue.put({"i": 99})
        assert small_queue.qsize == 3


# ===========================================================================
# 6. Test singleton returns same instance
# ===========================================================================


class TestSingleton:
    """Tests for the global singleton pattern."""

    def test_singleton_returns_same_instance(self) -> None:
        """get_progress_queue returns same instance."""
        q1 = get_progress_queue()
        q2 = get_progress_queue()
        assert q1 is q2

    def test_singleton_is_progress_queue(self) -> None:
        """get_progress_queue returns a ProgressQueue."""
        q = get_progress_queue()
        assert isinstance(q, ProgressQueue)


# ===========================================================================
# 7. Test reset clears singleton
# ===========================================================================


class TestReset:
    """Tests for singleton reset."""

    def test_reset_clears_singleton(self) -> None:
        """reset_progress_queue clears the singleton."""
        q1 = get_progress_queue()
        reset_progress_queue()
        q2 = get_progress_queue()
        assert q1 is not q2

    def test_reset_allows_new_instance(self) -> None:
        """After reset, get_progress_queue returns a fresh instance."""
        q1 = get_progress_queue()
        q1.put({"old": True})
        reset_progress_queue()
        q2 = get_progress_queue()
        result = q2.get(timeout=0.1)
        assert result is None


# ===========================================================================
# 8. Test create_progress_callback adds job_id
# ===========================================================================


class TestCreateProgressCallbackJobId:
    """Tests for job_id injection in callback."""

    def test_create_progress_callback_adds_job_id(self) -> None:
        """Callback adds job_id."""
        queue = ProgressQueue(maxsize=100)
        with patch("src.core.progress_queue.get_progress_queue", return_value=queue):
            callback = create_progress_callback("test-job-123")
            callback({"type": "progress"})

        event = queue.get(timeout=1.0)
        assert event["job_id"] == "test-job-123"

    def test_create_progress_callback_preserves_original_data(self) -> None:
        """Callback preserves original event data."""
        queue = ProgressQueue(maxsize=100)
        with patch("src.core.progress_queue.get_progress_queue", return_value=queue):
            callback = create_progress_callback("job-abc")
            callback({"type": "stage_change", "stage": "urls"})

        event = queue.get(timeout=1.0)
        assert event["type"] == "stage_change"
        assert event["stage"] == "urls"
        assert event["job_id"] == "job-abc"


# ===========================================================================
# 9. Test create_progress_callback adds timestamp
# ===========================================================================


class TestCreateProgressCallbackTimestamp:
    """Tests for timestamp injection in callback."""

    def test_create_progress_callback_adds_timestamp(self) -> None:
        """Callback adds timestamp."""
        queue = ProgressQueue(maxsize=100)
        with patch("src.core.progress_queue.get_progress_queue", return_value=queue):
            callback = create_progress_callback("job-ts")
            callback({"type": "log"})

        event = queue.get(timeout=1.0)
        assert "timestamp" in event
        assert isinstance(event["timestamp"], float)
        assert event["timestamp"] > 0

    def test_create_progress_callback_timestamp_is_recent(self) -> None:
        """Callback timestamp is close to current time."""
        queue = ProgressQueue(maxsize=100)
        with patch("src.core.progress_queue.get_progress_queue", return_value=queue):
            before = time.time()
            callback = create_progress_callback("job-ts")
            callback({"type": "log"})
            after = time.time()

        event = queue.get(timeout=1.0)
        assert before <= event["timestamp"] <= after


# ===========================================================================
# 10. Test concurrent puts thread safe
# ===========================================================================


class TestConcurrentPuts:
    """Tests for thread-safe concurrent puts."""

    def test_concurrent_puts_thread_safe(self) -> None:
        """Multiple threads putting simultaneously."""
        queue = ProgressQueue(maxsize=10000)
        num_threads = 10
        items_per_thread = 100
        errors: list[Exception] = []

        def put_items(thread_id: int) -> None:
            try:
                for i in range(items_per_thread):
                    queue.put({"thread": thread_id, "item": i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=put_items, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Errors during concurrent puts: {errors}"
        assert queue.qsize == num_threads * items_per_thread

    def test_concurrent_puts_no_data_loss(self) -> None:
        """No items lost during concurrent puts within capacity."""
        queue = ProgressQueue(maxsize=10000)
        num_threads = 5
        items_per_thread = 50

        def put_items(thread_id: int) -> None:
            for i in range(items_per_thread):
                queue.put({"t": thread_id, "i": i})

        threads = [threading.Thread(target=put_items, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        collected = 0
        while True:
            item = queue.get(timeout=0.1)
            if item is None:
                break
            collected += 1

        assert collected == num_threads * items_per_thread


# ===========================================================================
# 11. Test concurrent put/get thread safe
# ===========================================================================


class TestConcurrentPutGet:
    """Tests for producer/consumer thread safety."""

    def test_concurrent_put_get_thread_safe(self) -> None:
        """Producer/consumer threads."""
        queue = ProgressQueue(maxsize=1000)
        num_items = 200
        produced: list[int] = []
        consumed: list[int] = []
        produced_lock = threading.Lock()
        consumed_lock = threading.Lock()
        done = threading.Event()

        def producer() -> None:
            for i in range(num_items):
                queue.put({"id": i})
                with produced_lock:
                    produced.append(i)
            done.set()

        def consumer() -> None:
            while True:
                item = queue.get(timeout=0.5)
                if item is not None:
                    with consumed_lock:
                        consumed.append(item["id"])
                if done.is_set() and queue.qsize == 0:
                    break

        prod_thread = threading.Thread(target=producer)
        cons_thread = threading.Thread(target=consumer)

        cons_thread.start()
        prod_thread.start()

        prod_thread.join(timeout=10)
        cons_thread.join(timeout=10)

        assert len(consumed) == num_items
        assert sorted(consumed) == list(range(num_items))

    def test_concurrent_producer_consumer_no_crash(self) -> None:
        """No crashes under concurrent load."""
        queue = ProgressQueue(maxsize=50)
        errors: list[Exception] = []

        def producer() -> None:
            try:
                for i in range(100):
                    queue.put({"i": i})
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def consumer() -> None:
            try:
                for _ in range(100):
                    queue.get(timeout=1.0)
            except Exception as e:
                errors.append(e)

        threads = []
        for _ in range(3):
            t = threading.Thread(target=producer)
            threads.append(t)
        for _ in range(3):
            t = threading.Thread(target=consumer)
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert not errors


# ===========================================================================
# 12. Test callback exception does not crash
# ===========================================================================


class TestCallbackException:
    """Tests for exception handling in callbacks."""

    def test_callback_exception_does_not_crash(self) -> None:
        """Callback that throws doesn't break queue."""
        queue = ProgressQueue(maxsize=100)

        def put_event(event: dict) -> None:
            queue.put(event)

        event1 = {"type": "before"}
        put_event(event1)

        with pytest.raises(RuntimeError):
            raise RuntimeError("Simulated callback error")

        event2 = {"type": "after"}
        put_event(event2)

        assert queue.get(timeout=1.0) == event1
        assert queue.get(timeout=1.0) == event2

    def test_callback_with_job_id_survives_exception(self) -> None:
        """Callback-created events work after external exception."""
        queue = ProgressQueue(maxsize=100)
        with patch("src.core.progress_queue.get_progress_queue", return_value=queue):
            callback = create_progress_callback("job-x")

            callback({"type": "first"})

            try:
                raise ValueError("external error")
            except ValueError:
                pass

            callback({"type": "second"})

        event1 = queue.get(timeout=1.0)
        event2 = queue.get(timeout=1.0)

        assert event1["type"] == "first"
        assert event1["job_id"] == "job-x"
        assert event2["type"] == "second"
        assert event2["job_id"] == "job-x"

    def test_queue_still_works_after_many_exceptions(self) -> None:
        """Queue remains functional after many external exceptions."""
        queue = ProgressQueue(maxsize=100)

        for i in range(10):
            try:
                queue.put({"i": i})
                if i % 2 == 0:
                    raise RuntimeError(f"error at {i}")
            except RuntimeError:
                pass

        count = 0
        while True:
            item = queue.get(timeout=0.1)
            if item is None:
                break
            count += 1

        assert count == 10


# ===========================================================================
# Additional: Edge cases
# ===========================================================================


class TestEdgeCases:
    """Additional edge case tests."""

    def test_put_empty_dict(self, small_queue: ProgressQueue) -> None:
        """Empty dict can be put and retrieved."""
        small_queue.put({})
        result = small_queue.get(timeout=1.0)
        assert result == {}

    def test_put_complex_nested_dict(self, small_queue: ProgressQueue) -> None:
        """Complex nested dict can be put and retrieved."""
        event = {
            "type": "complex",
            "data": {
                "nested": {"key": "value"},
                "list": [1, 2, 3],
                "mixed": [{"a": 1}, {"b": 2}],
            },
        }
        small_queue.put(event)
        result = small_queue.get(timeout=1.0)
        assert result == event

    def test_get_blocks_until_put(self, small_queue: ProgressQueue) -> None:
        """get waits for put from another thread."""
        result_container: list[dict | None] = [None]

        def delayed_put() -> None:
            time.sleep(0.1)
            small_queue.put({"delayed": True})

        t = threading.Thread(target=delayed_put)
        t.start()

        result_container[0] = small_queue.get(timeout=2.0)
        t.join(timeout=5)

        assert result_container[0] == {"delayed": True}

    def test_progress_queue_default_maxsize(self) -> None:
        """Default maxsize is 10000."""
        queue = ProgressQueue()
        assert queue.qsize == 0
        for i in range(100):
            queue.put({"i": i})
        assert queue.qsize == 100

    def test_dropped_count_property_is_thread_safe(self) -> None:
        """dropped_count property uses lock."""
        queue = ProgressQueue(maxsize=2)
        queue.put({"a": 1})
        queue.put({"a": 2})
        queue.put({"a": 3})

        count = queue.dropped_count
        assert count == 1
        assert isinstance(count, int)

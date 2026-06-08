from src.dashboard.fastapi.routers.sse_events import (
    _SequenceTracker,
)


class TestSequenceTracker:
    def test_next_starts_at_one(self) -> None:
        """First call to next returns 1."""
        tracker = _SequenceTracker()
        assert tracker.next("job-1") == 1

    def test_next_increments(self) -> None:
        """Subsequent calls increment."""
        tracker = _SequenceTracker()
        assert tracker.next("job-1") == 1
        assert tracker.next("job-1") == 2
        assert tracker.next("job-1") == 3

    def test_next_independent_per_job(self) -> None:
        """Different jobs have independent counters."""
        tracker = _SequenceTracker()
        assert tracker.next("job-a") == 1
        assert tracker.next("job-b") == 1
        assert tracker.next("job-a") == 2
        assert tracker.next("job-b") == 2

    def test_reset_sets_counter_to_zero(self) -> None:
        """reset sets counter to 0 so next returns 1."""
        tracker = _SequenceTracker()
        tracker.next("job-1")
        tracker.next("job-1")
        tracker.reset("job-1")
        assert tracker.next("job-1") == 1

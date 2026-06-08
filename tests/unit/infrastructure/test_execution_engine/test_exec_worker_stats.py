import unittest

from src.infrastructure.execution_engine.load_balancer import WorkerStats


class TestWorkerStats(unittest.TestCase):
    def test_defaults(self) -> None:
        stats = WorkerStats(worker_id="w1")
        assert stats.active_tasks == 0
        assert stats.completed_tasks == 0
        assert stats.failed_tasks == 0
        assert stats.backpressure_factor == 1.0

    def test_total_tasks(self) -> None:
        stats = WorkerStats(worker_id="w1", completed_tasks=5, failed_tasks=3)
        assert stats.total_tasks == 8

    def test_is_overloaded(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=11)
        assert stats.is_overloaded is True

    def test_is_not_overloaded(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=5)
        assert stats.is_overloaded is False

    def test_is_idle(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=0, completed_tasks=5)
        assert stats.is_idle is True

    def test_is_not_idle(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=1)
        assert stats.is_idle is False

    def test_record_completion_success(self) -> None:
        stats = WorkerStats(worker_id="w1")
        stats.record_start()
        stats.record_completion(1.5, success=True)
        assert stats.active_tasks == 0
        assert stats.completed_tasks == 1
        assert stats.avg_task_duration_seconds == 1.5

    def test_record_completion_failure(self) -> None:
        stats = WorkerStats(worker_id="w1")
        stats.record_start()
        stats.record_completion(2.0, success=False)
        assert stats.failed_tasks == 1

    def test_compute_backpressure_no_tasks(self) -> None:
        stats = WorkerStats(worker_id="w1")
        bp = stats.compute_backpressure()
        assert bp == 1.0

    def test_compute_backpressure_with_tasks(self) -> None:
        stats = WorkerStats(worker_id="w1", active_tasks=5, completed_tasks=10, failed_tasks=0)
        bp = stats.compute_backpressure()
        assert 0.0 <= bp <= 1.0

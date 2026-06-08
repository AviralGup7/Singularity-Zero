import unittest

from src.infrastructure.execution_engine.models import (
    TaskResult,
    TaskStatus,
)


class TestTaskResult(unittest.TestCase):
    def test_result_success(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.SUCCESS)
        assert result.success is True
        assert result.failed is False

    def test_result_failed(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.FAILED)
        assert result.success is False
        assert result.failed is True

    def test_result_timed_out(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.TIMED_OUT)
        assert result.success is False
        assert result.failed is True

    def test_result_skipped(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.SKIPPED)
        assert result.success is False
        assert result.failed is False

    def test_result_defaults(self) -> None:
        result = TaskResult(task_id="t1", task_name="test", status=TaskStatus.PENDING)
        assert result.result is None
        assert result.error is None
        assert result.exception is None
        assert result.duration_seconds == 0.0
        assert result.attempts == 1
        assert result.worker_id is None

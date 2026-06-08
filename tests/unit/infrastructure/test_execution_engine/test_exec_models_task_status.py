import unittest

from src.infrastructure.execution_engine.models import (
    TaskStatus,
)


class TestTaskStatus(unittest.TestCase):
    def test_status_values(self) -> None:
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.QUEUED.value == "queued"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.SUCCESS.value == "success"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.CANCELLED.value == "cancelled"
        assert TaskStatus.TIMED_OUT.value == "timed_out"
        assert TaskStatus.SKIPPED.value == "skipped"

import unittest

from src.infrastructure.execution_engine.models import (
    TaskPriority,
)


class TestTaskPriority(unittest.TestCase):
    def test_priority_values(self) -> None:
        assert TaskPriority.CRITICAL.value == 0
        assert TaskPriority.HIGH.value == 1
        assert TaskPriority.NORMAL.value == 2
        assert TaskPriority.LOW.value == 3
        assert TaskPriority.BACKGROUND.value == 4

    def test_priority_ordering(self) -> None:
        assert TaskPriority.CRITICAL < TaskPriority.HIGH
        assert TaskPriority.HIGH < TaskPriority.NORMAL
        assert TaskPriority.LOW < TaskPriority.BACKGROUND

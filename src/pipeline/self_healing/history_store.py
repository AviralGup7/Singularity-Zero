from __future__ import annotations

from collections import defaultdict

from src.core.contracts.health import CorrectiveAction


class CorrectionHistoryStore:
    """Tracks rolling success rates of corrective actions and determines escalation."""

    def __init__(self, window_size: int = 10, failure_threshold: float = 0.40) -> None:
        self.window_size = max(1, int(window_size))
        self.failure_threshold = float(failure_threshold)
        # Never require more samples than the rolling window can hold.
        self._min_samples = min(3, self.window_size)
        # Maps action to list of booleans (True for success, False for failure)
        self._history: dict[CorrectiveAction, list[bool]] = defaultdict(list)

    def record(self, action: CorrectiveAction, success: bool) -> None:
        history = self._history[action]
        history.append(success)
        if len(history) > self.window_size:
            history.pop(0)

    def should_escalate(self, action: CorrectiveAction) -> bool:
        history = self._history[action]
        if len(history) < self._min_samples:
            return False
        failures = history.count(False)
        failure_rate = failures / len(history)
        return failure_rate >= self.failure_threshold

from collections import defaultdict
from typing import Dict, List
from src.core.contracts.health import CorrectiveAction

class CorrectionHistoryStore:
    """Tracks rolling success rates of corrective actions and determines escalation."""

    def __init__(self, window_size: int = 10, failure_threshold: float = 0.40) -> None:
        self.window_size = window_size
        self.failure_threshold = failure_threshold
        # Maps action to list of booleans (True for success, False for failure)
        self._history: Dict[CorrectiveAction, List[bool]] = defaultdict(list)

    def record(self, action: CorrectiveAction, success: bool) -> None:
        history = self._history[action]
        history.append(success)
        if len(history) > self.window_size:
            history.pop(0)

    def should_escalate(self, action: CorrectiveAction) -> bool:
        history = self._history[action]
        # Only evaluate if we have a representative sample (e.g., at least 3 attempts)
        if len(history) < 3:
            return False
        failures = history.count(False)
        failure_rate = failures / len(history)
        return failure_rate >= self.failure_threshold

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from src.core.models.entities import SEVERITY_LEVELS


class StopCondition(ABC):
    @abstractmethod
    def __call__(self, finding: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
        pass

    def __or__(self, other: StopCondition) -> StopConditionOr:
        return StopConditionOr(self, other)


class StopConditionOr(StopCondition):
    def __init__(self, left: StopCondition, right: StopCondition) -> None:
        self.left = left
        self.right = right

    def __call__(self, finding: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
        return self.left(finding, findings) or self.right(finding, findings)


class StopOnFirstFinding(StopCondition):
    def __call__(self, finding: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
        return len(findings) >= 1


class StopOnN(StopCondition):
    def __init__(self, n: int) -> None:
        self.n = n

    def __call__(self, finding: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
        return len(findings) >= self.n


class StopOnSeverity(StopCondition):
    def __init__(self, threshold: str) -> None:
        self.threshold_index = SEVERITY_LEVELS.index(threshold)

    def __call__(self, finding: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
        for f in findings:
            severity = f.get("severity", "info")
            if severity in SEVERITY_LEVELS:
                if SEVERITY_LEVELS.index(severity) <= self.threshold_index:
                    return True
        return False


class StopOnPattern(StopCondition):
    def __init__(self, pattern: re.Pattern) -> None:
        self.pattern = pattern

    def __call__(self, finding: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
        for f in findings:
            for issue in f.get("issues", []):
                if self.pattern.search(issue):
                    return True
        return False

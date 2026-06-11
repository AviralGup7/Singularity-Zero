"""Endpoint intelligence scoring utilities."""

from typing import Any


def _parameter_sensitivity_score(suggestions: list[dict[str, Any]]) -> int:
    """Calculate parameter sensitivity score from suggestions."""
    if not suggestions:
        return 0
    score = 0
    for suggestion in suggestions:
        param = str(suggestion.get("parameter", "")).lower()
        if any(kw in param for kw in ("id", "token", "key", "secret", "password", "auth")):
            score = max(score, 4)
        elif any(kw in param for kw in ("user", "email", "name", "role")):
            score = max(score, 3)
        elif any(kw in param for kw in ("type", "action", "mode")):
            score = max(score, 2)
        else:
            score = max(score, 1)
    return score

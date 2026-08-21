"""Severity normalization without HTTP clients."""

from __future__ import annotations

ALIASES = {
    "crit": "critical",
    "sev-critical": "critical",
    "sev-high": "high",
    "sev-medium": "medium",
    "sev-low": "low",
    "informational": "info",
    "information": "info",
}

CANONICAL = ("critical", "high", "medium", "low", "info")
RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def normalize_severity(raw: object) -> str:
    value = str(raw or "medium").strip().lower()
    value = ALIASES.get(value, value)
    return value if value in CANONICAL else "medium"


def at_least(severity: object, floor: object) -> bool:
    return RANK.get(normalize_severity(severity), 0) >= RANK.get(normalize_severity(floor), 0)

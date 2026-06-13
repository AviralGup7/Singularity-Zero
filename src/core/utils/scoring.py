"""Domain-neutral scoring utilities for parameter and signal weighting.

This module provides shared scoring functions used by both recon and
analysis packages without creating cross-layer dependencies.
"""

import re

# Pre-compiled regex patterns for token shape detection
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_IP_RE = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|169\.254\.)")

PARAMETER_WEIGHTS = {
    "callback": 3,
    "dest": 3,
    "destination": 3,
    "id": 2,
    "next": 2,
    "redirect": 2,
    "resource": 2,
    "return": 2,
    "target": 3,
    "token": 3,
    "uri": 3,
    "url": 4,
    "webhook": 4,
}

SIGNAL_WEIGHTS = {
    "callback": 3,
    "cross_host_target": 3,
    "dangerous_scheme": 3,
    "id": 2,
    "internal_host_reference": 3,
    "redirect": 2,
    "same_host_redirect": 2,
    "token": 3,
    "url": 3,
}


def parameter_weight(name: str, *, value: str = "", location: str = "query") -> int:
    """Calculate the security-relevant weight of a parameter."""
    lowered = str(name or "").strip().lower()
    if lowered in PARAMETER_WEIGHTS:
        base_weight = PARAMETER_WEIGHTS[lowered]
    else:
        base_weight = 1
        for token, weight in PARAMETER_WEIGHTS.items():
            if token in lowered:
                base_weight = weight
                break
    location_bonus = {"path": 1, "body": 1, "header": 2, "query": 0}.get(location, 0)
    value_bonus = 0
    if value:
        value_stripped = value.strip()
        if value_stripped.isdigit() and any(
            token in lowered for token in ("id", "key", "ref", "num")
        ):
            value_bonus = 2
        elif _UUID_RE.search(value_stripped):
            value_bonus = 2
        elif "://" in value_stripped or value_stripped.startswith("//"):
            value_bonus = 3
        elif _IP_RE.search(value_stripped):
            value_bonus = 3
    return min(base_weight + location_bonus + value_bonus, 10)


def signal_weight(signal: str) -> int:
    """Calculate the weight of a detection signal."""
    lowered = str(signal or "").strip().lower()
    for token, weight in SIGNAL_WEIGHTS.items():
        if token in lowered:
            return weight
    return 1

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


# ---------------------------------------------------------------------------
# Confidence scoring (extracted from analysis.helpers.scoring)
# ---------------------------------------------------------------------------

_CONFIDENCE_SCORE_WEIGHT = 0.025
_CONFIDENCE_SIGNAL_WEIGHT = 0.015
_CONFIDENCE_CAP = 0.96
_CONFIDENCE_MAX_TOTAL_BONUS = 0.35
_CONFIDENCE_MAX_TOTAL_PENALTY = 0.30


def normalized_confidence(
    *,
    base: float,
    score: int = 0,
    signals: list[str] | tuple[str, ...] | set[str] | None = None,
    bonuses: list[float] | tuple[float, ...] | None = None,
    cap: float = _CONFIDENCE_CAP,
) -> float:
    """Compute a bounded, capped-additive confidence score (R3).

    Bonuses are summed and capped at ``_CONFIDENCE_MAX_TOTAL_BONUS`` and
    penalties are clamped to ``-_CONFIDENCE_MAX_TOTAL_PENALTY`` so that
    additive scoring cannot compound past safe ceilings.
    """
    signal_values = [signal_weight(signal) for signal in (signals or [])]
    positive_bonuses = [value for value in (bonuses or []) if value > 0]
    negative_bonuses = [value for value in (bonuses or []) if value < 0]
    bonus_total = min(sum(positive_bonuses), _CONFIDENCE_MAX_TOTAL_BONUS)
    penalty_total = max(sum(negative_bonuses), -abs(_CONFIDENCE_MAX_TOTAL_PENALTY))
    confidence = (
        base
        + min(score, 10) * _CONFIDENCE_SCORE_WEIGHT
        + min(sum(signal_values), 10) * _CONFIDENCE_SIGNAL_WEIGHT
        + bonus_total
        + penalty_total
    )
    return round(min(max(confidence, 0.0), cap), 2)


def apply_bounded_confidence(
    *,
    base: float,
    score: int = 0,
    signals: list[str] | tuple[str, ...] | set[str] | None = None,
    bonuses: list[float] | tuple[float, ...] | None = None,
    cap: float = _CONFIDENCE_CAP,
    max_total_bonus: float = _CONFIDENCE_MAX_TOTAL_BONUS,
    max_total_penalty: float = _CONFIDENCE_MAX_TOTAL_PENALTY,
) -> float:
    """Bounded confidence helper exposing tunables for downstream callers."""
    signal_values = [signal_weight(signal) for signal in (signals or [])]
    positive_bonuses = [value for value in (bonuses or []) if value > 0]
    negative_bonuses = [value for value in (bonuses or []) if value < 0]
    bonus_total = min(sum(positive_bonuses), max_total_bonus)
    penalty_total = max(sum(negative_bonuses), -abs(max_total_penalty))
    confidence = (
        base
        + min(score, 10) * _CONFIDENCE_SCORE_WEIGHT
        + min(sum(signal_values), 10) * _CONFIDENCE_SIGNAL_WEIGHT
        + bonus_total
        + penalty_total
    )
    return round(min(max(confidence, 0.0), cap), 2)


# ---------------------------------------------------------------------------
# Severity scoring (extracted from analysis.helpers._constants)
# ---------------------------------------------------------------------------

_SEVERITY_SCORE_MAP = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}


def severity_score(severity: str) -> int:
    """Map a severity string to a numeric score.

    Args:
        severity: Severity level string (critical, high, medium, low, info).

    Returns:
        Numeric score (10-100).
    """
    return _SEVERITY_SCORE_MAP.get(severity.lower(), 10)

"""Scoring utilities for the analysis pipeline.

Contains parameter weighting, signal weighting, confidence normalization,
token shape detection, and replay likelihood calculation.
Extracted from helpers.py for better separation of concerns.
"""

import re
from typing import Any

from src.core.utils.scoring import (
    PARAMETER_WEIGHTS as PARAMETER_WEIGHTS,
    SIGNAL_WEIGHTS as SIGNAL_WEIGHTS,
    parameter_weight as parameter_weight,
    signal_weight as signal_weight,
)

# Pre-compiled regex patterns for token shape detection
JWT_LIKE_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_API_KEY_RE = re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{24,}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
_STRIPE_KEY_RE = re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")
_LONG_ALNUM_RE = re.compile(r"\b[A-Za-z0-9]{32,}\b")
_HEX_ONLY_RE = re.compile(r"^[a-f0-9]{32,}$", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_IP_RE = re.compile(r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|169\.254\.)")

HIGH_RISK_LOCATION_ORDER = {
    "response_body": 0,
    "referer_risk": 1,
    "header": 2,
    "query_parameter": 3,
    "unknown": 4,
}

LOCATION_SEVERITY = {
    "response_body": "high",
    "referer_risk": "high",
    "header": "medium",
    "query_parameter": "medium",
    "unknown": "low",
}


# Normalized confidence weights
_CONFIDENCE_SCORE_WEIGHT = 0.025
_CONFIDENCE_SIGNAL_WEIGHT = 0.015
_CONFIDENCE_CAP = 0.96
# Maximum total positive contribution that bonuses can add (R3/R8).
_CONFIDENCE_MAX_TOTAL_BONUS = 0.35
# Maximum total negative contribution (penalties).
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


# Re-export the bounded helper from the validator config layer so callers
# that import from src.analysis.helpers.scoring (R3, R8) get a uniform
# surface.
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


def token_shape(value: str) -> str:
    """Identify the shape/type of a token value."""
    from src.analysis.helpers import decode_candidate_value

    decoded = decode_candidate_value(value)
    if JWT_LIKE_RE.search(decoded):
        return "jwt_like"
    if decoded.lower().startswith("bearer "):
        return "bearer_token"
    if _AWS_KEY_RE.search(decoded):
        return "aws_access_key"
    if _API_KEY_RE.search(decoded):
        return "api_key"
    if _GITHUB_TOKEN_RE.search(decoded):
        return "github_token"
    if _SLACK_TOKEN_RE.search(decoded):
        return "slack_token"
    if _STRIPE_KEY_RE.search(decoded):
        return "stripe_key"
    if _LONG_ALNUM_RE.search(decoded) and len(decoded) >= 32:
        return "session_id"
    if _HEX_ONLY_RE.search(decoded):
        return "hex_token"
    if len(decoded) <= 12 and decoded.isalnum():
        return "oauth_code"
    return "generic"


# Replay likelihood weights
_REPLAY_BASE_WEIGHT = 0.35
_REPLAY_RESPONSE_BODY_BONUS = 0.3
_REPLAY_REFERER_RISK_BONUS = 0.18
_REPLAY_JWT_LIKE_BONUS = 0.15
_REPLAY_REPEAT_BONUS_PER_COUNT = 0.04
_REPLAY_MAX_LIKELIHOOD = 0.98


def replay_likelihood(location: str, token_shapes: list[str], repeat_count: int) -> float:
    base = _REPLAY_BASE_WEIGHT
    if str(location).lower() == "response_body":
        base += _REPLAY_RESPONSE_BODY_BONUS
    elif str(location).lower() == "referer_risk":
        base += _REPLAY_REFERER_RISK_BONUS
    if "jwt_like" in token_shapes:
        base += _REPLAY_JWT_LIKE_BONUS
    if repeat_count >= 2:
        base += min(0.18, repeat_count * _REPLAY_REPEAT_BONUS_PER_COUNT)
    return round(min(base, _REPLAY_MAX_LIKELIHOOD), 2)


def token_location_severity(location: str) -> str:
    return LOCATION_SEVERITY.get(str(location or "").strip().lower(), "low")


def sort_token_targets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            HIGH_RISK_LOCATION_ORDER.get(str(item.get("location", "unknown")).lower(), 9),
            -int(item.get("leak_count", 1)),
            item.get("url", ""),
        ),
    )


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

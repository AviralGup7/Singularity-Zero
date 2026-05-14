"""Scoring utilities for the analysis pipeline.

Contains parameter weighting, signal weighting, confidence normalization,
token shape detection, and replay likelihood calculation.
Extracted from helpers.py for better separation of concerns.
"""

import re
from typing import Any

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
    lowered = str(signal or "").strip().lower()
    for token, weight in SIGNAL_WEIGHTS.items():
        if token in lowered:
            return weight
    return 1


# Normalized confidence weights
_CONFIDENCE_SCORE_WEIGHT = 0.025
_CONFIDENCE_SIGNAL_WEIGHT = 0.015
_CONFIDENCE_CAP = 0.96


def normalized_confidence(
    *,
    base: float,
    score: int = 0,
    signals: list[str] | tuple[str, ...] | set[str] | None = None,
    bonuses: list[float] | tuple[float, ...] | None = None,
    cap: float = _CONFIDENCE_CAP,
) -> float:
    signal_values = [signal_weight(signal) for signal in (signals or [])]
    confidence = (
        base + min(score, 10) * _CONFIDENCE_SCORE_WEIGHT + min(sum(signal_values), 10) * _CONFIDENCE_SIGNAL_WEIGHT + sum(bonuses or [])
    )
    return round(min(confidence, cap), 2)


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

# Replay likelihood weights
_REPLAY_BASE_WEIGHT = 0.35
_REPLAY_RESPONSE_BODY_BONUS = 0.3
_REPLAY_REFERER_RISK_BONUS = 0.18
_REPLAY_JWT_LIKE_BONUS = 0.15
_REPLAY_REPEAT_BONUS_PER_COUNT = 0.04
_REPLAY_MAX_LIKELIHOOD = 0.98


def severity_score(severity: str) -> int:
    """Map a severity string to a numeric score.

    Args:
        severity: Severity level string (critical, high, medium, low, info).

    Returns:
        Numeric score (10-100).
    """
    return _SEVERITY_SCORE_MAP.get(severity.lower(), 10)

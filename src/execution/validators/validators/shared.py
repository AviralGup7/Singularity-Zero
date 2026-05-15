"""Shared utilities and constants for validation modules.

Provides status mapping, result normalization, and shared confidence
calculation constants used across SSRF, redirect, and IDOR validators.
"""

from typing import Any

from src.core.models import ValidationResult
from src.execution.validators.status import ValidationStatus

# Confidence calculation constants shared across validators
SSRF_CONFIDENCE_BASE = 0.44
SSRF_CONFIDENCE_CAP = 0.97

REDIRECT_CONFIDENCE_BASE = 0.44
REDIRECT_CONFIDENCE_CAP = 0.97

IDOR_CONFIDENCE_BASE = 0.46
IDOR_CONFIDENCE_CAP = 0.96


def map_validation_status(item: dict[str, Any]) -> ValidationStatus:
    """Map a raw status string from validation results to a ValidationStatus enum.

    Handles various status formats including 'confirmed', 'success', 'ok_confirmed',
    'failed', 'error', and defaults to INCONCLUSIVE for unrecognized values.
    """
    raw_status = str(item.get("status", "")).strip().lower()
    if raw_status in {"confirmed", "success", "ok_confirmed"}:
        return ValidationStatus.CONFIRMED
    if raw_status in {"failed", "error"}:
        return ValidationStatus.FAILED
    return ValidationStatus.INCONCLUSIVE


def to_validation_result(
    item: dict[str, Any], *, validator: str, category: str
) -> ValidationResult:
    url = str(item.get("url", "")).strip()
    status = map_validation_status(item)
    if not url:
        status = ValidationStatus.FAILED
    return ValidationResult(
        validator=validator,
        category=category,
        status=status.value,
        url=url,
        confidence=float(item.get("confidence", 0.0) or 0.0),
        in_scope=bool(item.get("in_scope", True)),
        scope_reason=str(item.get("scope_reason", "scope_not_evaluated")),
        evidence=dict(item.get("evidence", {})) if isinstance(item.get("evidence"), dict) else {},
        http=dict(item.get("http", {})) if isinstance(item.get("http"), dict) else {},
        error=dict(item.get("error", {})) if isinstance(item.get("error"), dict) else {},
        validation_actions=list(item.get("validation_actions", []))
        if isinstance(item.get("validation_actions"), list)
        else [],
    )


def build_confidence_explanation(
    base_confidence: float,
    bonuses: list[float],
    category: str,
    validation_state: str = "",
    signals: list[str] | None = None,
) -> str:
    """Build a human-readable explanation of how validation confidence was calculated.

    Provides transparent reasoning behind the confidence score, showing
    which factors contributed positively or negatively.

    Args:
        base_confidence: The base confidence value before bonuses.
        bonuses: List of bonus/penalty values applied.
        category: The vulnerability category (idor, ssrf, redirect, etc.).
        validation_state: The validation state (confirmed, heuristic, etc.).
        signals: List of detection signals.

    Returns:
        Human-readable confidence explanation string.
    """
    if base_confidence >= 0.8:
        level = "High"
    elif base_confidence >= 0.6:
        level = "Moderate"
    elif base_confidence >= 0.4:
        level = "Low-moderate"
    else:
        level = "Low"

    parts: list[str] = [f"{level} confidence ({base_confidence:.2f})"]

    if validation_state:
        parts.append(f"state: {validation_state}")

    positive = [b for b in bonuses if b > 0]
    negative = [b for b in bonuses if b < 0]

    if positive:
        total_positive = sum(positive)
        parts.append(f"+{total_positive:.2f} from {'+'.join(f'{b:.2f}' for b in positive[:3])}")
    if negative:
        total_negative = sum(negative)
        parts.append(f"{total_negative:.2f} from {'+'.join(f'{b:.2f}' for b in negative[:3])}")

    if signals:
        strong_signals = [
            s
            for s in signals
            if any(
                kw in s.lower()
                for kw in ("confirmed", "multi_strategy", "strong", "internal", "dangerous")
            )
        ]
        if strong_signals:
            parts.append(f"strong signals: {', '.join(strong_signals[:3])}")

    return f"{category.upper()}: {'; '.join(parts)}."


def build_validation_explanation(
    category: str,
    validation_state: str,
    confidence: float,
    url: str,
    signals: list[str] | None = None,
    edge_case_notes: list[str] | None = None,
) -> str:
    """Build a comprehensive explanation of a validation result.

    Combines the validation state, confidence reasoning, and any edge case
    notes into a single human-readable explanation for the analyst.

    Args:
        category: The vulnerability category.
        validation_state: The validation state (confirmed, heuristic, etc.).
        confidence: The final confidence score.
        url: The validated URL.
        signals: List of detection signals.
        edge_case_notes: List of edge case considerations.

    Returns:
        Human-readable validation explanation string.
    """
    parts: list[str] = []

    # Validation state explanation
    state_explanations = {
        "multi_strategy_confirmed": "Multiple independent mutation strategies confirmed the vulnerability.",
        "strong_response_similarity": "Response similarity below 0.4 strongly indicates access control weakness.",
        "response_similarity_match": "Response comparison with mutated identifiers returned similar results.",
        "heuristic_candidate": "Endpoint matches known vulnerability patterns but lacks active confirmation.",
        "active_ready": "Endpoint is suitable for active validation with controlled callback infrastructure.",
        "passive_only": "Only passive indicators detected — active validation recommended.",
        "confirmed": "Vulnerability confirmed through active validation.",
        "unconfirmed": "Active validation did not confirm the vulnerability.",
    }
    state_desc = state_explanations.get(validation_state, f"Validation state: {validation_state}.")
    parts.append(state_desc)

    # Confidence level
    if confidence >= 0.8:
        parts.append(f"High confidence ({confidence:.2f}) supports this finding.")
    elif confidence >= 0.6:
        parts.append(f"Moderate confidence ({confidence:.2f}) — manual review recommended.")
    elif confidence >= 0.4:
        parts.append(f"Low-moderate confidence ({confidence:.2f}) — further validation advised.")
    else:
        parts.append(
            f"Low confidence ({confidence:.2f}) — likely false positive or needs more evidence."
        )

    # Signal context
    if signals:
        parts.append(f"Detection signals: {', '.join(signals[:5])}.")

    # Edge case notes
    if edge_case_notes:
        parts.extend(edge_case_notes)

    return f"[{category.upper()}] {' '.join(parts)}"

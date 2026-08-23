"""Confidence helpers for detection plugins and findings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Score:
    confidence: float
    severity: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
            "reasons": list(self.reasons),
        }


_SEVERITY_FLOOR = {
    "info": 0.2,
    "low": 0.35,
    "medium": 0.5,
    "high": 0.7,
    "critical": 0.85,
}


def clamp(value: float) -> float:
    return min(max(float(value), 0.0), 1.0)


def blend(base: float, *deltas: float) -> float:
    total = base + sum(deltas)
    return clamp(total)


def score_finding(
    *,
    severity: str,
    plugin_confidence: float = 0.5,
    evidence_points: int = 0,
    false_positive_hits: int = 0,
    corroborated: bool = False,
) -> Score:
    reasons: list[str] = []
    floor = _SEVERITY_FLOOR.get(str(severity or "info").lower(), 0.3)
    confidence = max(floor, plugin_confidence)
    reasons.append(f"severity:{severity}")
    if evidence_points:
        bump = min(0.2, 0.04 * evidence_points)
        confidence = blend(confidence, bump)
        reasons.append(f"evidence:{evidence_points}")
    if corroborated:
        confidence = blend(confidence, 0.08)
        reasons.append("corroborated")
    if false_positive_hits:
        confidence = blend(confidence, -0.12 * min(false_positive_hits, 3))
        reasons.append(f"fp:{false_positive_hits}")
    return Score(
        confidence=confidence, severity=str(severity or "info").lower(), reasons=tuple(reasons)
    )


def rank(scores: list[Score]) -> list[Score]:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return sorted(
        scores, key=lambda item: (order.get(item.severity, 0), item.confidence), reverse=True
    )

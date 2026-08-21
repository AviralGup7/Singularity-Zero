"""False-positive rules applied to finding titles / evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FpHit:
    rule_id: str
    reason: str
    weight: float


_RULES: tuple[tuple[str, str, float, str], ...] = (
    ("info-only", r"\b(info|informational)\b", 0.4, "informational wording"),
    ("missing-evidence", r"\bTODO evidence\b", 0.8, "placeholder evidence"),
    ("example-host", r"example\.(com|org|net)", 0.7, "example hostname"),
    ("localhost", r"\blocalhost\b|\b127\.0\.0\.1\b", 0.5, "loopback target"),
    ("generic-xss", r"^possible xss$", 0.6, "generic xss title"),
    ("generic-sqli", r"^possible sql injection$", 0.6, "generic sqli title"),
    ("waf-block", r"\baccess denied\b|\bforbidden\b", 0.3, "waf wording"),
)


def evaluate(title: str, evidence: str = "") -> list[FpHit]:
    blob = f"{title}\n{evidence}".lower()
    hits: list[FpHit] = []
    for rule_id, pattern, weight, reason in _RULES:
        if re.search(pattern, blob, re.IGNORECASE):
            hits.append(FpHit(rule_id=rule_id, reason=reason, weight=weight))
    return hits


def fp_score(title: str, evidence: str = "") -> float:
    hits = evaluate(title, evidence)
    if not hits:
        return 0.0
    total = 1.0
    for hit in hits:
        total *= 1.0 - hit.weight
    return round(1.0 - total, 3)


def likely_false_positive(title: str, evidence: str = "", *, threshold: float = 0.55) -> bool:
    return fp_score(title, evidence) >= threshold

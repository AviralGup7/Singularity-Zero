"""Attack chain result model for chained validation.

Represents a detected attack chain pattern and its validation outcome.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ChainValidation:
    """A triggered chain validation."""

    chain_pattern: str
    description: str
    findings: list[dict[str, Any]]
    confidence: float
    validation_action: str
    priority: str = "high"
    validation_status: str = "pending"
    validation_result: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_db_row(self, chain_id: str) -> dict:
        """Convert to database row."""
        import json

        return {
            "chain_id": chain_id,
            "pattern_name": self.chain_pattern,
            "description": self.description,
            "finding_ids": json.dumps([f.get("id", f.get("url", "")) for f in self.findings]),
            "confidence": self.confidence,
            "risk_score": self._compute_risk_score(),
            "validation_status": self.validation_status,
            "validation_result": self.validation_result,
            "detected_at": self.detected_at.isoformat(),
        }

    def _compute_risk_score(self) -> float:
        """Compute risk score from chain findings."""
        severity_scores = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0,
        }
        max_sev = (
            max(severity_scores.get(f.get("severity", "low"), 1.0) for f in self.findings)
            if self.findings
            else 1.0
        )

        confidences = [f.get("confidence", 0.5) for f in self.findings]
        geom_mean = max(0.01, confidences[0]) ** (1.0 / len(confidences)) if confidences else 0.5

        length_bonus = 1.0 + 0.1 * len(self.findings)
        return round(max_sev * geom_mean * length_bonus, 4)

"""False-positive pattern model for the FP tracking subsystem.

Represents a learned false-positive pattern with Bayesian probability
tracking and automatic suppression action selection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class FPPattern:
    """A learned false-positive pattern."""

    pattern_id: str
    category: str
    status_codes: set[int] = field(default_factory=set)
    body_indicators: list[str] = field(default_factory=list)
    header_indicators: dict[str, str] = field(default_factory=dict)
    response_similarity_threshold: float = 0.9
    fp_probability: float = 0.5
    confidence: float = 0.0
    occurrence_count: int = 0
    confirmed_fp_count: int = 0
    confirmed_tp_count: int = 0
    is_active: bool = True
    suppression_action: str = "downgrade"  # suppress, downgrade, flag
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def create(
        cls,
        category: str,
        status_codes: set[int] | None = None,
        body_indicators: list[str] | None = None,
        header_indicators: dict[str, str] | None = None,
    ) -> FPPattern:
        """Create a new FP pattern."""
        import hashlib

        raw = f"{category}:{sorted(status_codes or set())}:{body_indicators or []}"
        pattern_id = f"fp-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"

        now = datetime.now(UTC)
        return cls(
            pattern_id=pattern_id,
            category=category,
            status_codes=status_codes or set(),
            body_indicators=body_indicators or [],
            header_indicators=header_indicators or {},
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )

    def update(self, is_fp: bool, is_tp: bool) -> None:
        """Update pattern statistics using Bayesian updating."""
        self.occurrence_count += 1
        if is_fp:
            self.confirmed_fp_count += 1
        if is_tp:
            self.confirmed_tp_count += 1

        # Bayesian update: Beta(alpha, beta) mean
        alpha = self.confirmed_fp_count + 1
        beta = self.confirmed_tp_count + 1
        self.fp_probability = alpha / (alpha + beta)

        # Confidence increases with sample size
        variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1))
        self.confidence = 1.0 - min(1.0, variance * 100)

        # Deactivate if confident it's NOT an FP
        if self.fp_probability < 0.3 and self.confidence > 0.8:
            self.is_active = False

        # Escalate suppression based on FP probability
        if self.fp_probability > 0.95 and self.occurrence_count > 10:
            self.suppression_action = "suppress"
        elif self.fp_probability > 0.8 and self.occurrence_count > 5:
            self.suppression_action = "downgrade"
        else:
            self.suppression_action = "flag"

        self.last_seen = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)

    def to_db_row(self) -> dict:
        """Convert to database row dict."""
        import json

        return {
            "pattern_id": self.pattern_id,
            "category": self.category,
            "status_code_pattern": json.dumps(sorted(self.status_codes)),
            "body_pattern": json.dumps(self.body_indicators),
            "header_pattern": json.dumps(self.header_indicators),
            "response_similarity": self.response_similarity_threshold,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "occurrence_count": self.occurrence_count,
            "confirmed_fp_count": self.confirmed_fp_count,
            "confirmed_tp_count": self.confirmed_tp_count,
            "fp_probability": self.fp_probability,
            "confidence": self.confidence,
            "is_active": self.is_active,
            "suppression_action": self.suppression_action,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_db_row(cls, row: dict) -> FPPattern:
        """Create from database row dict."""
        import json

        return cls(
            pattern_id=row["pattern_id"],
            category=row["category"],
            status_codes=set(json.loads(row["status_code_pattern"]))
            if row.get("status_code_pattern")
            else set(),
            body_indicators=json.loads(row["body_pattern"]) if row.get("body_pattern") else [],
            header_indicators=json.loads(row["header_pattern"])
            if row.get("header_pattern")
            else {},
            response_similarity_threshold=row.get("response_similarity", 0.9),
            fp_probability=row.get("fp_probability", 0.5),
            confidence=row.get("confidence", 0.0),
            occurrence_count=row.get("occurrence_count", 0),
            confirmed_fp_count=row.get("confirmed_fp_count", 0),
            confirmed_tp_count=row.get("confirmed_tp_count", 0),
            is_active=bool(row.get("is_active", True)),
            suppression_action=row.get("suppression_action", "downgrade"),
            first_seen=datetime.fromisoformat(row["first_seen"]) if row.get("first_seen") else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row.get("last_seen") else None,
            created_at=datetime.fromisoformat(row["created_at"])
            if row.get("created_at")
            else datetime.now(UTC),
            updated_at=datetime.fromisoformat(row["updated_at"])
            if row.get("updated_at")
            else datetime.now(UTC),
        )

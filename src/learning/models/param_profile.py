"""Parameter profile model for semantic parameter intelligence.

Captures the semantic classification and historical behavior of
a parameter across scans.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ParameterProfile:
    """Semantic profile of a single parameter."""

    profile_id: str
    parameter_name: str
    canonical_type: str  # One of 18 categories
    sub_type: str | None = None
    entity_context: str | None = None
    endpoint_context: str | None = None
    location: str = "query"
    sensitivity_level: str = "public"
    fuzz_strategy: str = "generic"
    historical_findings: int = 0
    historical_fp_rate: float = 0.0
    classification_confidence: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def create(
        cls,
        parameter_name: str,
        canonical_type: str,
        **kwargs: Any,
    ) -> ParameterProfile:
        """Create a new parameter profile."""
        import hashlib

        raw = f"{parameter_name}:{canonical_type}"
        profile_id = f"pp-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"

        now = datetime.now(UTC)
        return cls(
            profile_id=profile_id,
            parameter_name=parameter_name,
            canonical_type=canonical_type,
            first_seen=now,
            last_seen=now,
            updated_at=now,
            **kwargs,
        )

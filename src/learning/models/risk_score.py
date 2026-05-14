"""Risk score model for the adaptive risk-ranking engine.

Stores the components of an adaptive risk score so that the scoring
can be audited, tuned, and blended with static scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class RiskScore:
    """Adaptive risk score for an endpoint-category pair."""

    score_id: str
    run_id: str
    endpoint: str
    host: str
    category: str
    prior_risk: float
    likelihood_ratio: float
    recency_weight: float
    context_modifier: float
    exploration_bonus: float
    correlation_amplifier: float
    final_score: float
    score_components: dict[str, Any] = field(default_factory=dict)
    computed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @classmethod
    def compute(
        cls,
        run_id: str,
        endpoint: str,
        host: str,
        category: str,
        prior_risk: float,
        likelihood_ratio: float,
        recency_weight: float,
        context_modifier: float,
        exploration_bonus: float,
        correlation_amplifier: float,
    ) -> RiskScore:
        """Compute the final adaptive score from components.

        final_score = prior_risk × likelihood_ratio × recency_weight ×
                      context_modifier × (1 + exploration_bonus) × correlation_amplifier
        """
        final = (
            prior_risk
            * likelihood_ratio
            * recency_weight
            * context_modifier
            * (1.0 + exploration_bonus)
            * correlation_amplifier
        )

        import hashlib

        raw = f"{run_id}:{endpoint}:{host}:{category}"
        score_id = f"rs-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"

        components = {
            "prior_risk": prior_risk,
            "likelihood_ratio": likelihood_ratio,
            "recency_weight": recency_weight,
            "context_modifier": context_modifier,
            "exploration_bonus": exploration_bonus,
            "correlation_amplifier": correlation_amplifier,
        }

        return cls(
            score_id=score_id,
            run_id=run_id,
            endpoint=endpoint,
            host=host,
            category=category,
            prior_risk=round(prior_risk, 6),
            likelihood_ratio=round(likelihood_ratio, 6),
            recency_weight=round(recency_weight, 6),
            context_modifier=round(context_modifier, 6),
            exploration_bonus=round(exploration_bonus, 6),
            correlation_amplifier=round(correlation_amplifier, 6),
            final_score=round(final, 6),
            score_components=components,
        )

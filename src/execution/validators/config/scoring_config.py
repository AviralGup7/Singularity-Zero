"""Scoring configuration and bounded-confidence helpers.

R3: Replace additive confidence scoring with a bounded model.
R8: Make confidence thresholds configurable per validator.

The bounded model is:

    confidence = clamp(base + score_contribution + signal_contribution + bonus_total,
                       floor, cap)

where ``bonus_total`` is itself clamped to ``max_total_bonus`` so that no
combination of bonuses can compound past a safe ceiling. ``score_contribution``
and ``signal_contribution`` use small per-unit weights with their own per-source
caps so high raw scores cannot dominate the final confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Tiny per-unit weights (kept compatible with src.analysis.helpers.scoring).
_SCORE_WEIGHT = 0.025
_SIGNAL_WEIGHT = 0.015
_SCORE_CAP_UNITS = 10
_SIGNAL_CAP_UNITS = 10


@dataclass(frozen=True)
class ScoringConfig:
    """Per-validator bounded scoring configuration.

    Attributes:
        base: Starting confidence before any score, signal or bonus
            contribution.
        cap: Hard upper bound on the final confidence.
        floor: Hard lower bound on the final confidence.
        max_total_bonus: Maximum positive contribution that bonuses may add.
            Negative bonuses (penalties) are not subject to this cap and
            are summed independently.
        max_total_penalty: Maximum total negative contribution. Penalties
            beyond this absolute value are clamped.
        score_weight: Per-unit weight applied to the raw score (clamped to
            ``_SCORE_CAP_UNITS``).
        signal_weight: Per-unit weight applied to summed signal weights.
        required_signals: Iterable of signal names that must all be present
            for the result to be considered ``confirmed`` (used by R5).
        min_independent_signals: Minimum number of distinct ``required_signals``
            categories that must agree to confirm a finding.
    """

    base: float = 0.45
    cap: float = 0.95
    floor: float = 0.0
    max_total_bonus: float = 0.35
    max_total_penalty: float = 0.30
    score_weight: float = _SCORE_WEIGHT
    signal_weight: float = _SIGNAL_WEIGHT
    required_signals: tuple[str, ...] = ()
    min_independent_signals: int = 1

    def merged_with(self, overrides: dict[str, Any] | None) -> ScoringConfig:
        """Return a copy with overrides applied. Unknown keys are ignored."""
        if not overrides:
            return self
        data = {
            "base": float(overrides.get("base", self.base)),
            "cap": float(overrides.get("cap", self.cap)),
            "floor": float(overrides.get("floor", self.floor)),
            "max_total_bonus": float(
                overrides.get("max_total_bonus", self.max_total_bonus)
            ),
            "max_total_penalty": float(
                overrides.get("max_total_penalty", self.max_total_penalty)
            ),
            "score_weight": float(overrides.get("score_weight", self.score_weight)),
            "signal_weight": float(
                overrides.get("signal_weight", self.signal_weight)
            ),
            "required_signals": tuple(
                str(value)
                for value in overrides.get("required_signals", self.required_signals)
            ),
            "min_independent_signals": int(
                overrides.get(
                    "min_independent_signals", self.min_independent_signals
                )
            ),
        }
        return ScoringConfig(**data)


# Default per-validator scoring constants. These mirror the previously
# hard-coded values in src/execution/validators/validators/shared.py and the
# individual validator modules, but expressed via the bounded model.
DEFAULT_SCORING_CONFIG: dict[str, ScoringConfig] = {
    "ssrf": ScoringConfig(
        base=0.44,
        cap=0.97,
        max_total_bonus=0.40,
        required_signals=(
            "callback_oob_confirmed",
            "internal_host_reference",
            "cloud_metadata_reference",
        ),
        min_independent_signals=1,
    ),
    "redirect": ScoringConfig(
        base=0.44,
        cap=0.97,
        max_total_bonus=0.35,
    ),
    "idor": ScoringConfig(
        base=0.46,
        cap=0.96,
        max_total_bonus=0.35,
        max_total_penalty=0.30,
        required_signals=(
            "multi_strategy_confirmed",
            "strong_response_similarity",
        ),
    ),
    "csrf": ScoringConfig(
        base=0.48,
        cap=0.92,
        max_total_bonus=0.30,
    ),
    "file_upload": ScoringConfig(
        base=0.48,
        cap=0.92,
        max_total_bonus=0.40,
        required_signals=("dangerous_accepted", "executable_uploaded"),
    ),
    "xss": ScoringConfig(
        base=0.50,
        cap=0.94,
        max_total_bonus=0.35,
        required_signals=(
            "payload_reflected",
            "dangerous_context",
            "baseline_diff_observed",
        ),
        min_independent_signals=2,
    ),
    "ssti": ScoringConfig(
        base=0.45,
        cap=0.90,
        max_total_bonus=0.35,
        required_signals=(
            "math_evaluation",
            "template_error",
            "baseline_diff_observed",
        ),
        min_independent_signals=2,
    ),
    "token_reuse": ScoringConfig(
        base=0.50,
        cap=0.95,
        max_total_bonus=0.35,
    ),
    # New validators added in R7.
    "cors": ScoringConfig(
        base=0.45,
        cap=0.93,
        max_total_bonus=0.35,
        required_signals=(
            "reflected_origin",
            "wildcard_with_credentials",
            "null_origin_allowed",
        ),
    ),
    "race_condition": ScoringConfig(
        base=0.45,
        cap=0.92,
        max_total_bonus=0.30,
        required_signals=("inconsistent_response", "duplicate_success"),
        min_independent_signals=1,
    ),
    "jwt_weakness": ScoringConfig(
        base=0.45,
        cap=0.95,
        max_total_bonus=0.40,
        required_signals=(
            "alg_none_accepted",
            "weak_secret_cracked",
            "kid_injection",
        ),
        min_independent_signals=1,
    ),
    "cache_poisoning": ScoringConfig(
        base=0.45,
        cap=0.92,
        max_total_bonus=0.35,
        required_signals=("cached_unkeyed_input", "x_cache_hit_with_payload"),
    ),
    "graphql_abuse": ScoringConfig(
        base=0.45,
        cap=0.92,
        max_total_bonus=0.35,
        required_signals=(
            "introspection_exposed",
            "batch_amplification",
            "deeply_nested_accepted",
        ),
    ),
}


@dataclass(frozen=True)
class BoundedScoreResult:
    """Detailed bounded-confidence calculation result."""

    confidence: float
    base: float
    score_contribution: float
    signal_contribution: float
    bonus_total: float
    penalty_total: float
    bonus_total_capped: float
    penalty_total_capped: float
    pre_clamp_value: float


def apply_bounded_confidence(
    *,
    config: ScoringConfig,
    score: int = 0,
    signal_weights: list[int] | tuple[int, ...] | None = None,
    bonuses: list[float] | tuple[float, ...] | None = None,
) -> BoundedScoreResult:
    """Compute confidence using a bounded, capped-additive model.

    Args:
        config: Per-validator ``ScoringConfig``.
        score: Raw integer score from the candidate finder.
        signal_weights: Per-signal weight contributions. Their sum is capped
            at ``_SIGNAL_CAP_UNITS`` before being multiplied by
            ``config.signal_weight``.
        bonuses: List of bonus/penalty floats. Positive values are summed
            and then capped at ``config.max_total_bonus``. Negative values
            are summed and clamped at ``-config.max_total_penalty``.

    Returns:
        ``BoundedScoreResult`` exposing the final confidence and intermediate
        contributions for explainability.
    """
    score_units = min(max(int(score or 0), 0), _SCORE_CAP_UNITS)
    score_contribution = score_units * config.score_weight

    signal_sum = min(sum(signal_weights or []), _SIGNAL_CAP_UNITS)
    signal_contribution = signal_sum * config.signal_weight

    positive_bonuses = [value for value in (bonuses or []) if value > 0]
    negative_bonuses = [value for value in (bonuses or []) if value < 0]
    bonus_total = sum(positive_bonuses)
    penalty_total = sum(negative_bonuses)

    bonus_total_capped = min(bonus_total, config.max_total_bonus)
    penalty_total_capped = max(penalty_total, -abs(config.max_total_penalty))

    pre_clamp = (
        float(config.base)
        + score_contribution
        + signal_contribution
        + bonus_total_capped
        + penalty_total_capped
    )
    confidence = max(min(pre_clamp, config.cap), config.floor)
    return BoundedScoreResult(
        confidence=round(confidence, 2),
        base=config.base,
        score_contribution=round(score_contribution, 4),
        signal_contribution=round(signal_contribution, 4),
        bonus_total=round(bonus_total, 4),
        penalty_total=round(penalty_total, 4),
        bonus_total_capped=round(bonus_total_capped, 4),
        penalty_total_capped=round(penalty_total_capped, 4),
        pre_clamp_value=round(pre_clamp, 4),
    )


def confidence_from_config(
    validator_name: str,
    *,
    score: int = 0,
    signal_weights: list[int] | tuple[int, ...] | None = None,
    bonuses: list[float] | tuple[float, ...] | None = None,
    config_overrides: dict[str, dict[str, Any]] | None = None,
) -> BoundedScoreResult:
    """Convenience wrapper that resolves a validator's config and applies it."""
    base = DEFAULT_SCORING_CONFIG.get(validator_name, ScoringConfig())
    if config_overrides:
        base = base.merged_with(config_overrides.get(validator_name))
    return apply_bounded_confidence(
        config=base,
        score=score,
        signal_weights=signal_weights,
        bonuses=bonuses,
    )


_REQUIRED_SIGNAL_GROUPS_FIELD = field(default_factory=dict)


@dataclass(frozen=True)
class SignalConfirmationPolicy:
    """Policy used to decide whether a finding is "confirmed".

    Allows requiring multiple independent signal categories before a finding
    is promoted to ``confirmed`` status (R3, R5).
    """

    required_groups: dict[str, tuple[str, ...]] = _REQUIRED_SIGNAL_GROUPS_FIELD
    min_groups_required: int = 1

    def is_confirmed(self, observed_signals: list[str]) -> bool:
        if not self.required_groups:
            return False
        observed = {str(signal).strip().lower() for signal in observed_signals}
        groups_satisfied = 0
        for members in self.required_groups.values():
            if any(member.lower() in observed for member in members):
                groups_satisfied += 1
        return groups_satisfied >= max(1, int(self.min_groups_required))

"""Calibration configuration: per-engagement signal requirements and overrides.

Used by R5 (XSS/SSTI baselines), R6 (token replay) and R7 (new validators) to
require independent signal agreement before promoting a finding to
``confirmed`` status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.execution.validators.config.scoring_config import ScoringConfig


@dataclass(frozen=True)
class CalibrationConfig:
    """Per-engagement calibration tunables.

    Attributes:
        min_independent_signals: Default minimum number of independent
            signals required to confirm a finding (used when a per-validator
            ``ScoringConfig`` does not override ``min_independent_signals``).
        signal_agreement_threshold: Fractional threshold (0..1) describing the
            minimum ratio of agreeing signal categories to total observed.
        ssrf_active_probe_enabled: Whether active callback probing is
            permitted (R4).
        xss_baseline_required: Whether XSS confirmation requires a baseline
            non-XSS payload comparison (R5).
        ssti_baseline_required: Whether SSTI confirmation requires a baseline
            non-template payload comparison (R5).
        token_replay_block_by_default: If True, token replay is skipped
            unless the user has explicitly opted in via
            ``validation_settings.extensions.blackbox_validation.authorized_replay``.
        max_concurrent_race_workers: Maximum parallel workers for race
            condition probing (R7).
        cache_poisoning_unkeyed_headers: Headers used to probe for cache
            poisoning (default: ``X-Forwarded-Host``, ``X-Original-URL``,
            ``X-Host``).
        jwt_test_signatures: HMAC secrets to try when cracking a JWT.
        graphql_introspection_query: The introspection query used to test
            whether a GraphQL endpoint is exposed.
    """

    min_independent_signals: int = 1
    signal_agreement_threshold: float = 0.5
    ssrf_active_probe_enabled: bool = True
    xss_baseline_required: bool = True
    ssti_baseline_required: bool = True
    token_replay_block_by_default: bool = True
    max_concurrent_race_workers: int = 5
    cache_poisoning_unkeyed_headers: tuple[str, ...] = (
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Host",
        "X-Forwarded-Scheme",
    )
    jwt_test_signatures: tuple[str, ...] = (
        "secret",
        "password",
        "changeme",
        "admin",
        "1234567890",
        "supersecret",
    )
    graphql_introspection_query: str = (
        "{__schema{queryType{name}mutationType{name}subscriptionType{name}"
        "types{name}}}"
    )
    per_validator_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)

    def scoring_for(self, validator_name: str, *, base: ScoringConfig) -> ScoringConfig:
        """Resolve a per-validator scoring config with calibration overrides."""
        overrides = self.per_validator_overrides.get(validator_name) or {}
        merged = base.merged_with(overrides)
        # Apply the engagement-wide min signal threshold only when the
        # per-validator config did not explicitly set its own.
        if (
            "min_independent_signals" not in overrides
            and merged.min_independent_signals < self.min_independent_signals
        ):
            return ScoringConfig(
                base=merged.base,
                cap=merged.cap,
                floor=merged.floor,
                max_total_bonus=merged.max_total_bonus,
                max_total_penalty=merged.max_total_penalty,
                score_weight=merged.score_weight,
                signal_weight=merged.signal_weight,
                required_signals=merged.required_signals,
                min_independent_signals=self.min_independent_signals,
            )
        return merged

"""Top-level validation config loader.

R8: Make confidence thresholds, scope policy and replay safety configurable
per engagement. Reads from ``validation_settings.extensions.blackbox_validation``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.execution.validators.config.calibration import CalibrationConfig
from src.execution.validators.config.replay_safety import ReplaySafetyConfig
from src.execution.validators.config.scoring_config import ScoringConfig

_SCOPE_RULES: dict[str, Any] = {
    "block_active_when_unscoped": True,
    "log_warning_when_unscoped": True,
    "treat_unscoped_as_out_of_scope": True,
}


@dataclass(frozen=True)
class ScopePolicy:
    """Scope-related policy flags.

    Attributes:
        block_active_when_unscoped: Skip active probing when no scope
            is configured (default True).
        log_warning_when_unscoped: Emit a warning when no scope is set.
        treat_unscoped_as_out_of_scope: Mark findings as out-of-scope
            when no scope is configured (default True).
    """

    block_active_when_unscoped: bool = True
    log_warning_when_unscoped: bool = True
    treat_unscoped_as_out_of_scope: bool = True


def _coerce_scope_policy(raw: dict[str, Any] | None) -> ScopePolicy:
    if not raw:
        return ScopePolicy()
    return ScopePolicy(
        block_active_when_unscoped=bool(raw.get("block_active_when_unscoped", True)),
        log_warning_when_unscoped=bool(raw.get("log_warning_when_unscoped", True)),
        treat_unscoped_as_out_of_scope=bool(raw.get("treat_unscoped_as_out_of_scope", True)),
    )


@dataclass(frozen=True)
class ValidationConfig:
    """Top-level validation configuration container.

    Attributes:
        scoring: Per-validator ``ScoringConfig`` mapping.
        calibration: Per-engagement calibration.
        replay_safety: Token replay safety settings.
        scope_policy: Scope enforcement policy.
        raw: The original raw validation_settings dict.
    """

    scoring: dict[str, ScoringConfig] = field(default_factory=dict)
    calibration: CalibrationConfig = field(default_factory=CalibrationConfig)
    replay_safety: ReplaySafetyConfig = field(default_factory=ReplaySafetyConfig)
    scope_policy: ScopePolicy = field(default_factory=ScopePolicy)
    raw: dict[str, Any] = field(default_factory=dict)

    def resolve_scoring(self, validator_name: str) -> ScoringConfig:
        """Return the ScoringConfig for ``validator_name`` applying calibration."""
        base = self.scoring.get(validator_name)
        if base is None:
            from src.execution.validators.config.scoring_config import (
                DEFAULT_SCORING_CONFIG,
            )

            base = DEFAULT_SCORING_CONFIG.get(validator_name, ScoringConfig())
        return self.calibration.scoring_for(validator_name, base=base)


def load_validation_config(
    validation_settings: dict[str, Any] | None,
) -> ValidationConfig:
    """Build a ValidationConfig from raw validation_settings.

    The expected shape is::

        validation_settings:
          extensions:
            blackbox_validation:
              scoring:
                <validator_name>:
                  base: 0.5
                  cap: 0.95
                  max_total_bonus: 0.35
              calibration:
                min_independent_signals: 1
                xss_baseline_required: true
                ssti_baseline_required: true
              token_replay_safety:
                authorized_replay: false
              scope:
                block_active_when_unscoped: true
    """
    raw_settings: dict[str, Any] = validation_settings or {}
    if not raw_settings:
        from src.execution.validators.config.scoring_config import (
            DEFAULT_SCORING_CONFIG,
        )

        return ValidationConfig(
            scoring=dict(DEFAULT_SCORING_CONFIG),
            calibration=CalibrationConfig(),
            replay_safety=ReplaySafetyConfig(),
            scope_policy=ScopePolicy(),
            raw={},
        )
    blackbox = raw_settings.get("extensions", {}).get("blackbox_validation", {}) or {}
    scoring_overrides = blackbox.get("scoring", {}) or {}
    calibration_cfg = CalibrationConfig(
        min_independent_signals=int(
            blackbox.get("calibration", {}).get("min_independent_signals", 1)
        ),
        signal_agreement_threshold=float(
            blackbox.get("calibration", {}).get("signal_agreement_threshold", 0.5)
        ),
        ssrf_active_probe_enabled=bool(
            blackbox.get("calibration", {}).get("ssrf_active_probe_enabled", True)
        ),
        xss_baseline_required=bool(
            blackbox.get("calibration", {}).get("xss_baseline_required", True)
        ),
        ssti_baseline_required=bool(
            blackbox.get("calibration", {}).get("ssti_baseline_required", True)
        ),
        token_replay_block_by_default=bool(
            blackbox.get("calibration", {}).get("token_replay_block_by_default", True)
        ),
        max_concurrent_race_workers=int(
            blackbox.get("calibration", {}).get("max_concurrent_race_workers", 5)
        ),
        cache_poisoning_unkeyed_headers=tuple(
            blackbox.get("calibration", {}).get(
                "cache_poisoning_unkeyed_headers",
                list(CalibrationConfig().cache_poisoning_unkeyed_headers),
            )
        ),
        jwt_test_signatures=tuple(
            blackbox.get("calibration", {}).get(
                "jwt_test_signatures", list(CalibrationConfig().jwt_test_signatures)
            )
        ),
        per_validator_overrides=scoring_overrides,
    )
    replay_safety = ReplaySafetyConfig(
        authorized_replay=bool(
            blackbox.get("token_replay_safety", {}).get("authorized_replay", False)
        ),
        max_replay_attempts_per_token=int(
            blackbox.get("token_replay_safety", {}).get("max_replay_attempts_per_token", 3)
        ),
        max_replay_attempts_per_host=int(
            blackbox.get("token_replay_safety", {}).get("max_replay_attempts_per_host", 5)
        ),
    )
    scope_policy = _coerce_scope_policy(blackbox.get("scope", {}))

    from src.execution.validators.config.scoring_config import (
        DEFAULT_SCORING_CONFIG,
    )

    scoring: dict[str, ScoringConfig] = dict(DEFAULT_SCORING_CONFIG)
    for validator_name, overrides in scoring_overrides.items():
        if not isinstance(overrides, dict):
            continue
        existing = scoring.get(validator_name, ScoringConfig())
        scoring[validator_name] = existing.merged_with(overrides)

    return ValidationConfig(
        scoring=scoring,
        calibration=calibration_cfg,
        replay_safety=replay_safety,
        scope_policy=scope_policy,
        raw=raw_settings,
    )

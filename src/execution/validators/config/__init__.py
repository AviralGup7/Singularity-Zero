"""Validation configuration and calibration layer.

Provides tunable scoring thresholds, bounded confidence helpers, safety
guardrails for token replay, and per-engagement calibration overrides.

Public surface:
- ``ScoringConfig``: per-validator base/cap/bonus configuration.
- ``CalibrationConfig``: per-engagement adjustments and signal requirements.
- ``ReplaySafetyConfig``: token replay safety guardrails.
- ``ValidationConfig``: top-level container loaded from settings.
- ``load_validation_config``: build a config from raw validation_settings.
- ``replay_safety_from_settings``: build a ReplaySafetyConfig from raw
    validation_settings (used by the engine runner).
- ``apply_bounded_confidence``: capped-additive scoring helper.
"""

from src.execution.validators.config.calibration import CalibrationConfig
from src.execution.validators.config.replay_safety import (
    ReplaySafetyConfig,
    replay_safety_from_settings,
)
from src.execution.validators.config.scoring_config import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
    apply_bounded_confidence,
)
from src.execution.validators.config.validation_config import (
    ScopePolicy,
    ValidationConfig,
    load_validation_config,
)

__all__ = [
    "CalibrationConfig",
    "DEFAULT_SCORING_CONFIG",
    "ReplaySafetyConfig",
    "ScoringConfig",
    "ScopePolicy",
    "ValidationConfig",
    "apply_bounded_confidence",
    "load_validation_config",
    "replay_safety_from_settings",
]

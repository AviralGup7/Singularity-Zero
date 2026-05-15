"""Event handling logic for runtime controls.

Handles building form defaults and applying runtime overrides to config.
"""

from typing import Any

from src.dashboard.registry import ANALYSIS_CHECK_OPTIONS

from .controls import (
    CONFIG_TOGGLE_CONTROLS,
    RUNTIME_NUMERIC_CONTROLS,
    RUNTIME_TOGGLE_CONTROLS,
)
from .widgets import (
    _ensure_nested_section,
    validate_control_value,
)


def build_form_defaults(config: dict[str, Any]) -> dict[str, str]:
    """Build default form values from current config."""
    defaults = {spec.name: spec.default_value(config) for spec in RUNTIME_NUMERIC_CONTROLS}
    defaults.update({spec.name: spec.default_value(config) for spec in RUNTIME_TOGGLE_CONTROLS})
    for option in ANALYSIS_CHECK_OPTIONS:
        defaults[option["name"]] = (
            "1" if config.get("analysis", {}).get(option["name"], True) else "0"
        )
    return defaults


def apply_runtime_overrides(config: dict[str, Any], overrides: dict[str, str]) -> None:
    """Apply runtime override values to the config dict in-place."""
    for spec in RUNTIME_NUMERIC_CONTROLS:
        raw = overrides.get(spec.name)
        if raw in (None, ""):
            continue

        if spec.value_type == "float":
            try:
                parsed = float(str(raw))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{spec.name} must be a number.") from exc
            validated = validate_control_value(spec.name, parsed, RUNTIME_NUMERIC_CONTROLS)
            section = _ensure_nested_section(config, spec.path[:-1])
            section[spec.path[-1]] = validated
        else:
            try:
                parsed = int(str(raw))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{spec.name} must be an integer.") from exc
            validated = validate_control_value(spec.name, parsed, RUNTIME_NUMERIC_CONTROLS)
            section = _ensure_nested_section(config, spec.path[:-1])
            section[spec.path[-1]] = validated

    for toggle_spec in CONFIG_TOGGLE_CONTROLS:
        if toggle_spec.name not in overrides or toggle_spec.config_path is None:
            continue
        section = _ensure_nested_section(config, toggle_spec.config_path[:-1])
        section[toggle_spec.config_path[-1]] = overrides[toggle_spec.name] == "1"

    analysis = config.setdefault("analysis", {})
    for option in ANALYSIS_CHECK_OPTIONS:
        if option["name"] in overrides:
            analysis[option["name"]] = overrides[option["name"]] == "1"

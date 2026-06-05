"""Runtime controls for dashboard UI form generation and config overrides.

Defines utilities for applying runtime overrides to pipeline
configuration and building form defaults. The actual
``NumericControlSpec`` / ``ToggleControlSpec`` dataclasses and the
canonical list of runtime controls live in
:mod:`src.dashboard.controls.controls`; this module re-exports them so
legacy callers can keep importing from ``form_specs``.
"""

from typing import Any

from src.dashboard.controls.controls import (
    CONFIG_TOGGLE_CONTROLS,
    EXECUTION_TOGGLE_CONTROLS,
    RUNTIME_FORM_FIELD_NAMES,
    RUNTIME_NUMERIC_CONTROLS,
    RUNTIME_TOGGLE_CONTROLS,
    NumericControlSpec,
    ToggleControlSpec,
)
from src.dashboard.registry import ANALYSIS_CHECK_OPTIONS

__all__ = [
    "NumericControlSpec",
    "ToggleControlSpec",
    "RUNTIME_NUMERIC_CONTROLS",
    "RUNTIME_TOGGLE_CONTROLS",
    "RUNTIME_FORM_FIELD_NAMES",
    "EXECUTION_TOGGLE_CONTROLS",
    "CONFIG_TOGGLE_CONTROLS",
    "ANALYSIS_CHECK_OPTIONS",
    "build_form_defaults",
    "apply_runtime_overrides",
    "validate_control_value",
]


_CONTROL_LOOKUP: dict[str, NumericControlSpec] = {}


def _build_control_lookup() -> dict[str, NumericControlSpec]:
    lookup: dict[str, NumericControlSpec] = {}
    for spec in RUNTIME_NUMERIC_CONTROLS:
        lookup[spec.name] = spec
    return lookup


_CONTROL_LOOKUP = _build_control_lookup()




def validate_control_value(control_id: str, value: int | float) -> int | float:
    spec = _CONTROL_LOOKUP.get(control_id)
    if spec is None:
        raise ValueError(f"Unknown control: {control_id}")

    minimum = spec.minimum
    maximum = spec.maximum

    if maximum is not None and value > maximum * 10:
        raise ValueError(
            f"Value {value} for control '{control_id}' exceeds "
            f"the absolute safety threshold of {maximum * 10} "
            f"(10x the configured maximum of {maximum})."
        )

    if value < minimum:
        raise ValueError(
            f"Value {value} for control '{control_id}' is below the minimum of {minimum}."
        )

    if maximum is not None and value > maximum:
        return type(value)(maximum) if isinstance(value, float) else int(maximum)

    return value


def build_form_defaults(config: dict[str, Any]) -> dict[str, str]:
    defaults = {spec.name: spec.default_value(config) for spec in RUNTIME_NUMERIC_CONTROLS}
    defaults.update({spec.name: spec.default_value(config) for spec in RUNTIME_TOGGLE_CONTROLS})
    for option in ANALYSIS_CHECK_OPTIONS:
        defaults[option["name"]] = (
            "1" if config.get("analysis", {}).get(option["name"], True) else "0"
        )
    return defaults


def apply_runtime_overrides(config: dict[str, Any], overrides: dict[str, str]) -> None:
    for spec in RUNTIME_NUMERIC_CONTROLS:
        raw = overrides.get(spec.name)
        if raw in (None, ""):
            continue

        if spec.value_type == "float":
            try:
                parsed = float(str(raw))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{spec.name} must be a number.") from exc
            validated = validate_control_value(spec.name, parsed)
            section = _ensure_nested_section(config, spec.path[:-1])
            section[spec.path[-1]] = validated
        else:
            try:
                if isinstance(raw, (int, float)):
                    parsed = int(raw)
                else:
                    parsed = int(str(raw))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{spec.name} must be an integer.") from exc
            validated = validate_control_value(spec.name, parsed)
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


def _nested_get(config: dict[str, Any], path: tuple[str, ...], fallback: Any) -> Any:
    current: Any = config
    for segment in path:
        if not isinstance(current, dict):
            return fallback
        current = current.get(segment)
        if current is None:
            return fallback
    return current


def _ensure_nested_section(config: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    current: dict[str, Any] = config
    for segment in path:
        value = current.get(segment)
        if not isinstance(value, dict):
            value = {}
            current[segment] = value
        current = value
    return current


def _resolve_priority_limit_default(config: dict[str, Any]) -> Any:
    priority_limit = _nested_get(config, ("filters", "priority_limit"), 100)
    if isinstance(priority_limit, dict):
        return priority_limit.get("default", 100)
    return priority_limit


def _assign_int(
    target: dict[str, Any],
    key: str,
    raw_value: str | None,
    *,
    minimum: int = 1,
    target_key: str | None = None,
) -> None:
    if raw_value in (None, ""):
        return
    try:
        parsed = int(str(raw_value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be an integer.") from exc
    if parsed < minimum:
        raise ValueError(f"{key} must be at least {minimum}.")
    target[target_key or key] = parsed


def _assign_float(
    target: dict[str, Any],
    key: str,
    raw_value: str | None,
    *,
    minimum: float = 0.0,
    target_key: str | None = None,
) -> None:
    if raw_value in (None, ""):
        return
    try:
        parsed = float(str(raw_value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number.") from exc
    if parsed < minimum:
        raise ValueError(f"{key} must be at least {minimum}.")
    target[target_key or key] = parsed

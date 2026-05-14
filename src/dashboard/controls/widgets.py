"""UI widget definitions and nested config utilities.

Provides _nested_get, _ensure_nested_section, _resolve_priority_limit_default,
_assign_int, _assign_float, and validate_control_value.
"""

from typing import Any


def _nested_get(config: dict[str, Any], path: tuple[str, ...], fallback: Any) -> Any:
    """Safely traverse a nested dict path, returning fallback on miss."""
    current: Any = config
    for segment in path:
        if not isinstance(current, dict):
            return fallback
        current = current.get(segment)
        if current is None:
            return fallback
    return current


def _ensure_nested_section(config: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    """Ensure nested dict sections exist, creating empty dicts as needed."""
    current: dict[str, Any] = config
    for segment in path:
        value = current.get(segment)
        if not isinstance(value, dict):
            value = {}
            current[segment] = value
        current = value
    return current


def _resolve_priority_limit_default(config: dict[str, Any]) -> Any:
    """Resolve the priority_limit default from config, handling dict-wrapped values."""
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
    """Parse and assign an int value to target dict, skipping empty values."""
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
    """Parse and assign a float value to target dict, skipping empty values."""
    if raw_value in (None, ""):
        return
    try:
        parsed = float(str(raw_value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number.") from exc
    if parsed < minimum:
        raise ValueError(f"{key} must be at least {minimum}.")
    target[target_key or key] = parsed


def validate_control_value(control_id: str, value: int | float, controls: list) -> int | float:
    """Validate a numeric control value against its spec bounds."""
    spec = None
    for c in controls:
        if c.name == control_id:
            spec = c
            break
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

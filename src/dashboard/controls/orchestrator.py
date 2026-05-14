"""Main runtime controls orchestrator.

Provides the RuntimeControls class that coordinates control lookups,
form defaults, and override application.
"""

from typing import Any

from .controls import (
    CONFIG_TOGGLE_CONTROLS,
    EXECUTION_TOGGLE_CONTROLS,
    RUNTIME_FORM_FIELD_NAMES,
    RUNTIME_NUMERIC_CONTROLS,
    RUNTIME_TOGGLE_CONTROLS,
    NumericControlSpec,
    ToggleControlSpec,
)
from .event_handlers import apply_runtime_overrides, build_form_defaults
from .widgets import (
    validate_control_value,
)

_CONTROL_LOOKUP: dict[str, NumericControlSpec] = {}


def _build_control_lookup() -> dict[str, NumericControlSpec]:
    """Build a lookup dict from control name to NumericControlSpec."""
    lookup: dict[str, NumericControlSpec] = {}
    for spec in RUNTIME_NUMERIC_CONTROLS:
        lookup[spec.name] = spec
    return lookup


_CONTROL_LOOKUP = _build_control_lookup()


class RuntimeControls:
    """Orchestrator for runtime dashboard controls."""

    def __init__(self) -> None:
        self.numeric_controls = RUNTIME_NUMERIC_CONTROLS
        self.toggle_controls = RUNTIME_TOGGLE_CONTROLS
        self.execution_toggles = EXECUTION_TOGGLE_CONTROLS
        self.config_toggles = CONFIG_TOGGLE_CONTROLS
        self.form_field_names = RUNTIME_FORM_FIELD_NAMES
        self._lookup = _CONTROL_LOOKUP

    def get_numeric_control(self, name: str) -> NumericControlSpec | None:
        """Get a numeric control spec by name."""
        return self._lookup.get(name)

    def get_all_numeric_controls(self) -> list[NumericControlSpec]:
        """Get all numeric control specs."""
        return list(self.numeric_controls)

    def get_all_toggle_controls(self) -> list[ToggleControlSpec]:
        """Get all toggle control specs."""
        return list(self.toggle_controls)

    def build_form_defaults(self, config: dict[str, Any]) -> dict[str, str]:
        """Build default form values from config."""
        return build_form_defaults(config)

    def apply_overrides(self, config: dict[str, Any], overrides: dict[str, str]) -> None:
        """Apply runtime overrides to config in-place."""
        apply_runtime_overrides(config, overrides)

    def validate_value(self, control_id: str, value: int | float) -> int | float:
        """Validate a control value against its spec."""
        return validate_control_value(control_id, value, self.numeric_controls)

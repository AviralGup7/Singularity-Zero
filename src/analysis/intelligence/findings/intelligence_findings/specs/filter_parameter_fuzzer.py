"""Filter mutation changes response behavior spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Replay the observed filter change under the same context and compare whether visibility expands beyond the expected result set."


register_spec(
    (
        "filter_parameter_fuzzer",
        "behavioral_deviation",
        _severity,
        "Filter mutation changes response behavior",
        _description,
    )
)

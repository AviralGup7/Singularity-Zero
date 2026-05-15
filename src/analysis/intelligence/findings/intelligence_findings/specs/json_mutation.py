"""JSON-shaped parameter mutation changes API behavior spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    observations = item.get("observations", [])
    return "high" if any(obs.get("status_changed") for obs in observations) else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Replay the JSON-like object and array variants against the same API parameter and compare response schema, status, and authorization handling."


register_spec(
    (
        "json_mutation_attacks",
        "business_logic",
        _severity,
        "JSON-shaped parameter mutation changes API behavior",
        _description,
    )
)

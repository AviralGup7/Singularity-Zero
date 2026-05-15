"""Deep nested JSON object graph spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("traversal_score", 0) >= 14 else "low"


def _description(item: dict[str, Any]) -> str:
    return "Traverse the nested object graph carefully and look for identifiers, related objects, and embedded secrets or admin-only fields."


register_spec(
    (
        "nested_object_traversal",
        "anomaly",
        _severity,
        "Deep nested JSON object graph",
        _description,
    )
)

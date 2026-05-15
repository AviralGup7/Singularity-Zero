"""Admin or service login surface may use weak defaults spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Check safely for bootstrap credentials, setup flows, or unchanged admin defaults without brute forcing."


register_spec(
    (
        "default_credential_hints",
        "exposure",
        _severity,
        "Admin or service login surface may use weak defaults",
        _description,
    )
)

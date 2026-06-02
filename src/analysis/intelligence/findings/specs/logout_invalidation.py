"""Session may remain valid after logout spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if item.get("session_still_valid") else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Verify from a fresh client whether the pre-logout session still accesses the protected endpoint after logout."


register_spec(
    (
        "logout_invalidation_check",
        "broken_authentication",
        _severity,
        "Session may remain valid after logout",
        _description,
    )
)

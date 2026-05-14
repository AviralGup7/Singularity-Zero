"""Same endpoint varies across identity contexts spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "high" if float(item.get("body_similarity", 1.0)) < 0.7 else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Compare existing user, account, or tenant-scoped variants already observed in the crawl and verify whether the differences match expected ownership rules."


register_spec(
    (
        "cross_user_access_simulation",
        "access_control",
        _severity,
        "Same endpoint varies across identity contexts",
        _description,
    )
)

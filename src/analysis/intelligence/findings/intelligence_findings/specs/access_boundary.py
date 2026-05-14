"""Access boundary transition pattern detected spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    signals = item.get("signals", [])
    return "high" if "private_to_admin" in signals or "public_to_admin" in signals else "medium"


def _description(item: dict[str, Any]) -> str:
    return "Trace the related public, private, and admin views to confirm whether the same object family crosses trust boundaries."


register_spec(
    (
        "access_boundary_tracker",
        "access_control",
        _severity,
        "Access boundary transition pattern detected",
        _description,
    )
)

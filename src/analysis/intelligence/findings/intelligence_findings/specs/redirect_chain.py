"""Redirect chain behavior observed spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if item.get("cross_host") else "low"


def _description(item: dict[str, Any]) -> str:
    return "Review the full redirect chain and confirm whether multi-hop behavior crosses hosts or trust zones."


register_spec(
    (
        "redirect_chain_analyzer",
        "redirect",
        _severity,
        "Redirect chain behavior observed",
        _description,
    )
)

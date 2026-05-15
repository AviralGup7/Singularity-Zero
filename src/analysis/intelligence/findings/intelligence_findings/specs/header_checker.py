"""Missing security headers spec."""

from typing import Any

from src.analysis.helpers import build_manual_hint

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium" if len(item.get("issues", [])) >= 3 else "low"


def _description(item: dict[str, Any]) -> str:
    return build_manual_hint("misconfiguration", item.get("url", ""), item)


register_spec(
    ("header_checker", "misconfiguration", _severity, "Missing security headers", _description)
)

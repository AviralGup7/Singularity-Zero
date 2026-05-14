"""Cache poisoning indicator spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return (
        "high"
        if "host_header_reflection_in_cacheable_response" in item.get("issues", [])
        else "medium"
    )


def _description(item: dict[str, Any]) -> str:
    return "Verify whether cache keys include Host and forwarding headers and whether reflected content is cacheable."


register_spec(
    (
        "cache_poisoning_indicator_checker",
        "misconfiguration",
        _severity,
        "Cache poisoning indicator",
        _description,
    )
)

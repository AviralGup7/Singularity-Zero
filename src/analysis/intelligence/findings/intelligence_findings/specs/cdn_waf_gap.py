"""Inconsistent CDN or WAF coverage spec."""

from typing import Any

from . import register_spec


def _severity(item: dict[str, Any]) -> str:
    return "medium"


def _description(item: dict[str, Any]) -> str:
    return "Compare protected and unprotected endpoints on the same host for filtering gaps."


register_spec(
    (
        "cdn_waf_fingerprint_gap_checker",
        "misconfiguration",
        _severity,
        "Inconsistent CDN or WAF coverage",
        _description,
    )
)

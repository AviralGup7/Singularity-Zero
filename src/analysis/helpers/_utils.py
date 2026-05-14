"""Utility builders and JSON helpers."""

from typing import Any

from ._classification import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_auth_flow_endpoint,
)
from ._constants import SCHEMA_VERSION


def json_type_name(value: object) -> str:
    """Return the JSON type name for a Python value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def normalize_headers(response: dict[str, Any]) -> dict[str, str]:
    """Extract and normalize HTTP response headers to lowercase keys and string values."""
    return {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}


def build_validator_result(
    *,
    module: str,
    category: str,
    url: str,
    score: int,
    confidence: float,
    signals: list[str],
    validation_state: str,
    hint_message: str,
    **extra: Any,
) -> dict[str, Any]:
    """Build a standardized validator result dict."""
    return {
        "schema_version": SCHEMA_VERSION,
        "module": module,
        "category": category,
        "url": url,
        "endpoint_type": classify_endpoint(url),
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "auth_flow_endpoint": is_auth_flow_endpoint(url),
        "score": int(score),
        "confidence": round(float(confidence), 2),
        "signals": sorted({signal for signal in signals if signal}),
        "validation_state": validation_state,
        "hint_message": hint_message,
        **extra,
    }


def build_manual_hint(category: str, url: str, evidence: dict[str, Any] | None = None) -> str:
    """Build a manual testing hint message for a finding category."""
    details = evidence or {}
    endpoint_type = classify_endpoint(url)
    if category == "open_redirect":
        if "same_host_redirect" in details.get("signals", []):
            return "Swap the redirect target to an internal path like /admin and compare trust-boundary handling."
        return "Try both absolute and scheme-relative callback targets, then compare reflected versus followed redirects."
    if category == "ssrf":
        if details.get("validation_state") == "active_ready":
            return "Replace the sink value with a controlled callback host, then probe internal IP and dangerous-scheme variants."
        return "Test the sink with a callback URL, localhost metadata targets, and protocol variants to measure filtering."
    if category == "idor":
        if details.get("comparison"):
            return "Replay the mutated identifier under a lower-privileged session and compare key fields in both responses."
        return "Change one identifier at a time and compare authorization decisions across roles or tenant boundaries."
    if category == "token_leak":
        if str(details.get("location", "")).lower() == "response_body":
            return "Start with the rendered response leak, then trace where the token is consumed and whether it is replayable."
        return "Check whether the leaked token survives redirects, referers, or cached responses before rotating it."
    if category == "anomaly":
        return "Review the endpoint manually for hidden behaviors, backup artifacts, or debug-only routing."
    if endpoint_type == "API":
        return "Replay the request with small controlled parameter mutations and compare response shape, status, and data ownership."
    return "Review the endpoint manually and confirm whether the signal survives authenticated or cross-user replay."


def classify_object_family(url: str) -> str:
    """Classify the object family based on URL path patterns."""
    from urllib.parse import urlparse

    path = urlparse(url).path.lower()
    if any(token in path for token in ("/user_images", "/uploads", "/attachments", "/files")):
        return "uploaded_object"
    if any(token in path for token in ("/users", "/profiles", "/members")):
        return "user_object"
    if any(token in path for token in ("/orders", "/invoices", "/accounts")):
        return "business_object"
    return "generic_object"

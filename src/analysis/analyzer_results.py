"""Analyzer result builder for standardizing analysis output payloads.

Provides a unified builder function for creating analysis result dictionaries
with consistent endpoint classification and metadata.
"""

from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature


def build_analyzer_result(
    url: str,
    *,
    response: dict[str, Any] | None = None,
    status_code: int | None = None,
    include_endpoint_keys: bool = True,
    **extra: object,
) -> dict[str, Any]:
    """Build a standardized analyzer result dictionary.

    Args:
        url: The URL being analyzed.
        response: Optional HTTP response dict to extract status code from.
        status_code: Explicit status code (overrides response dict if provided).
        include_endpoint_keys: Whether to include endpoint signature keys.
        **extra: Additional key-value pairs to include in the result.

    Returns:
        Dictionary with url, endpoint metadata, status code, and extra fields.
    """
    normalized_url = str(url or "")
    resolved_status = status_code
    if resolved_status is None and isinstance(response, dict):
        resolved_status = response.get("status_code")
    payload: dict[str, Any] = {"url": normalized_url}
    if include_endpoint_keys and normalized_url:
        payload.update(
            {
                "endpoint_key": endpoint_signature(normalized_url),
                "endpoint_base_key": endpoint_base_key(normalized_url),
                "endpoint_type": classify_endpoint(normalized_url),
            }
        )
    elif normalized_url:
        payload["endpoint_type"] = classify_endpoint(normalized_url)
    if resolved_status is not None:
        payload["status_code"] = resolved_status
    payload.update(extra)
    return payload

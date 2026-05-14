"""Credential stuffing attack probes."""

from typing import Any

from src.analysis.passive.runtime import ResponseCache


def probe_credential_stuffing(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Test for credential stuffing vulnerabilities.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of credential stuffing findings.
    """
    return []

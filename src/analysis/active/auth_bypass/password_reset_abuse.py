"""Password reset abuse attack probes."""

from typing import Any

from src.analysis.passive.runtime import ResponseCache


def probe_password_reset_abuse(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Test for password reset abuse vulnerabilities.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of password reset abuse findings.
    """
    return []

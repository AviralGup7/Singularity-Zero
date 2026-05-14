"""API key candidate validation.

Delegates API key checklist execution to the api_test_integration module.
"""

from typing import Any

from src.core.plugins import register_plugin
from src.execution.validators.api_test_integration import run_api_key_checklist

VALIDATOR = "validator"


@register_plugin(VALIDATOR, "api_key_candidates")
def validate_api_key_candidates(
    runtime_inputs: dict[str, Any] | None, validation_settings: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Validate API key candidates found in URLs and responses.

    Args:
        runtime_inputs: Dict with 'urls' and 'responses' keys for analysis context.
        validation_settings: Optional settings with timeout and candidate limits.

    Returns:
        List of API key validation result dicts.
    """
    context = runtime_inputs or {}
    urls = context.get("urls") or []
    responses = context.get("responses") or []
    if not urls and not responses:
        return []

    settings = validation_settings or {}
    timeout = int(settings.get("api_key_timeout_seconds", 10))
    candidate_limit = int(settings.get("api_key_candidate_limit", 6))
    result = run_api_key_checklist(
        urls, responses, timeout=timeout, candidate_limit=candidate_limit
    )
    if result.get("status") not in {"completed", "none"}:
        return []
    return list(result.get("results", []))

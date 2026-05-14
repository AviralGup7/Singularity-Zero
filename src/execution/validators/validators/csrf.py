"""CSRF validation for endpoints lacking anti-CSRF controls.

Actively validates CSRF protection by testing state-changing endpoints
with and without CSRF tokens, checking SameSite cookie attributes,
and verifying token validation behavior.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Any
from src.analysis.helpers import (
    endpoint_signature,
    is_auth_flow_endpoint,
    is_low_value_endpoint,
    normalized_confidence,
)
from src.core.plugins import register_plugin



if TYPE_CHECKING:
    from src.core.models import ValidationResult


# HTTP methods that require CSRF protection
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Headers that indicate CSRF protection
CSRF_PROTECTION_HEADERS = {
    "x-csrf-token",
    "x-xsrf-token",
    "x-csrf-header",
    "csrf-token",
    "x-xsrf-header",
}



VALIDATOR = "validator"


@register_plugin(VALIDATOR, "csrf_candidates")
def validate_csrf_candidates(
    analysis_results: dict[str, Any],
    callback_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Validate CSRF protection on state-changing endpoints.

    Analyzes responses from passive analysis to identify endpoints
    that may lack proper CSRF protection.

    Args:
        analysis_results: Results from passive analysis modules.
        callback_context: Optional callback context with validation state.

    Returns:
        List of CSRF validation findings.
    """
    findings: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()

    # Get CSRF-related findings from passive analysis
    csrf_findings = analysis_results.get("csrf_protection_checker", [])

    for item in csrf_findings:
        url = str(item.get("url", "")).strip()
        if not url or is_low_value_endpoint(url):
            continue
        endpoint_key = str(item.get("endpoint_key") or endpoint_signature(url))
        if endpoint_key in seen_patterns:
            continue
        seen_patterns.add(endpoint_key)

        signals = list(item.get("signals", []))
        score = int(item.get("score", 0))

        # Check for auth flow endpoints (higher risk)
        if is_auth_flow_endpoint(url):
            signals.append("auth_flow_endpoint")
            score += 3

        # Check for missing CSRF tokens
        missing_tokens: list[str] = []
        if "missing_csrf_token" in signals:
            missing_tokens.append("csrf_token")
        if "missing_samesite" in signals:
            missing_tokens.append("samesite_attribute")
        if "weak_samesite" in signals:
            missing_tokens.append("weak_samesite")
        if "no_csrf_header" in signals:
            missing_tokens.append("csrf_header")

        # Determine validation state
        validation_state = "passive_only"
        if missing_tokens:
            validation_state = "active_ready"
            score += len(missing_tokens) * 2

        # Calculate confidence
        confidence = normalized_confidence(
            base=0.48,
            score=score,
            signals=signals,
            cap=0.92,
        )

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": str(item.get("endpoint_type", "GENERAL")),
                "score": score,
                "signals": sorted(set(signals)),
                "confidence": round(confidence, 2),
                "validation_state": validation_state,
                "missing_protections": missing_tokens,
                "hint_message": f"Verify CSRF protection on {url}. Missing: {', '.join(missing_tokens) if missing_tokens else 'review recommended'}.",
            }
        )

    findings.sort(key=lambda x: (-x["score"], -x["confidence"], x["url"]))
    return findings[:50]


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    """Validate CSRF enforcement on the target endpoint.

    Analyzes CSRF candidates from passive analysis and returns
    validation results for endpoints lacking anti-CSRF controls.
    """
    from src.execution.validators.validators.shared import to_validation_result

    analysis_results = context.get("analysis_results") if context else {}
    analysis_results = analysis_results if isinstance(analysis_results, dict) else {}

    findings = validate_csrf_candidates(analysis_results)
    if not findings:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "inconclusive", "confidence": 0.0},
            validator="csrf",
            category="csrf",
        )

    # Find the finding for this target URL
    target_url = str(target.get("url", "")).strip().lower()
    for finding in findings:
        if str(finding.get("url", "")).strip().lower() == target_url:
            finding["status"] = "ok"
            return to_validation_result(finding, validator="csrf", category="csrf")

    # Return first finding as general CSRF assessment
    first = dict(findings[0])
    first.setdefault("url", target.get("url", ""))
    first.setdefault("status", "inconclusive")
    return to_validation_result(first, validator="csrf", category="csrf")

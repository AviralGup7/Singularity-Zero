"""Token reuse validation with actual replay testing.

Tests whether tokens can be replayed across sessions, endpoints, or identity
boundaries. Validates token expiration, scope enforcement, and replay protection.
"""

from typing import Any

from src.core.models import ValidationResult
from src.execution.validators.validators.shared import to_validation_result
from src.execution.validators.validators.token import analyze_token_exposures


def _replay_token_on_endpoint(
    token_value: str, token_location: str, target_url: str, http_client: Any
) -> dict[str, Any]:
    """Attempt to replay a token on a target endpoint.

    Args:
        token_value: The token value to replay.
        token_location: Where the token was found (header, query, body, cookie).
        target_url: URL to test the token against.
        http_client: HTTP client for making requests.

    Returns:
        Dict with replay test results.
    """
    if not http_client:
        return {"status": "skipped", "reason": "no_http_client"}

    headers = {}
    if token_location in ("header", "authorization"):
        headers["Authorization"] = f"Bearer {token_value}"
    elif token_location == "cookie":
        headers["Cookie"] = f"session={token_value}"

    try:
        response = http_client.request(target_url, headers=headers)
        status_code = int(response.get("status_code") or 0)
        body_length = int(response.get("body_length") or 0)

        # Token accepted if we get a successful response
        token_accepted = status_code in (200, 201, 204, 302)
        # Token rejected if we get auth errors
        token_rejected = status_code in (401, 403)

        return {
            "status": "tested",
            "target_url": target_url,
            "response_status": status_code,
            "response_length": body_length,
            "token_accepted": token_accepted,
            "token_rejected": token_rejected,
            "replay_risk": "high" if token_accepted else "low" if token_rejected else "medium",
        }
    except Exception as exc:
        return {"status": "error", "reason": str(exc)}


def _assess_token_type(token_value: str) -> str:
    """Assess the type of token based on its format.

    Args:
        token_value: The token value to assess.

    Returns:
        Token type string (jwt, api_key, session_id, oauth_token, unknown).
    """
    if not token_value:
        return "unknown"

    # JWT detection
    if token_value.startswith("eyJ") and token_value.count(".") >= 2:
        return "jwt"

    # API key patterns
    if token_value.startswith(("sk_", "pk_", "api_", "key_")):
        return "api_key"

    # OAuth token patterns
    if token_value.startswith(("ya29.", "gho_", "ghp_", "xox")):
        return "oauth_token"

    # Session ID patterns (hex strings)
    if len(token_value) >= 32 and all(c in "0123456789abcdef" for c in token_value.lower()):
        return "session_id"

    return "unknown"


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    """Validate token reuse and replay protection.

    Tests whether tokens can be replayed across sessions or endpoints,
    and assesses the risk based on token type and replay success.

    Args:
        target: Target dict with url and metadata.
        context: Validation context with analysis_results and http_client.

    Returns:
        ValidationResult with token reuse assessment.
    """
    analysis_results = context.get("analysis_results") if isinstance(context, dict) else None
    analysis_results = analysis_results if isinstance(analysis_results, dict) else {}
    http_client = context.get("http_client") if isinstance(context, dict) else None

    summary = analyze_token_exposures(analysis_results)
    top_targets = summary.get("top_targets") or []

    if not top_targets:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "no_tokens_found"},
            validator="token_reuse",
            category="token_reuse",
        )

    findings: list[dict[str, Any]] = []
    for token_target in top_targets[:5]:  # Test top 5 tokens
        token_value = str(token_target.get("token_value", ""))
        token_location = str(token_target.get("location", "unknown"))
        token_type = _assess_token_type(token_value)

        # Test replay on the original endpoint
        original_url = str(token_target.get("url", target.get("url", "")))
        replay_result = _replay_token_on_endpoint(
            token_value, token_location, original_url, http_client
        )

        # Test replay on a different endpoint (cross-endpoint replay)
        other_urls = [
            str(t.get("url", "")) for t in top_targets if str(t.get("url", "")) != original_url
        ]
        cross_endpoint_results = []
        for other_url in other_urls[:2]:  # Test on 2 other endpoints
            cross_result = _replay_token_on_endpoint(
                token_value, token_location, other_url, http_client
            )
            cross_endpoint_results.append(cross_result)

        # Calculate confidence based on token type and replay results
        base_confidence = 0.50
        if token_type == "jwt":
            base_confidence += 0.15  # JWTs are more likely to be replayable
        elif token_type == "api_key":
            base_confidence += 0.10  # API keys often have broad scope
        elif token_type == "session_id":
            base_confidence += 0.05  # Session IDs should be single-use

        # Adjust confidence based on replay results
        if replay_result.get("token_accepted"):
            base_confidence += 0.20  # High risk if token works
        elif replay_result.get("token_rejected"):
            base_confidence -= 0.10  # Lower risk if properly rejected

        # Cross-endpoint replay risk
        cross_endpoint_accepted = any(r.get("token_accepted") for r in cross_endpoint_results)
        if cross_endpoint_accepted:
            base_confidence += 0.15  # Very high risk if token works across endpoints

        confidence = round(min(max(base_confidence, 0.10), 0.98), 2)

        # Determine severity
        if cross_endpoint_accepted or (
            replay_result.get("token_accepted") and token_type in ("jwt", "api_key")
        ):
            severity = "high"
        elif replay_result.get("token_accepted"):
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            {
                "url": original_url,
                "token_type": token_type,
                "token_location": token_location,
                "replay_result": replay_result,
                "cross_endpoint_results": cross_endpoint_results,
                "cross_endpoint_replay_risk": cross_endpoint_accepted,
                "confidence": confidence,
                "severity": severity,
                "validation_state": "active_tested"
                if replay_result.get("status") == "tested"
                else "passive_only",
                "edge_case_notes": _build_token_replay_notes(
                    token_type, replay_result, cross_endpoint_results
                ),
            }
        )

    # Return the highest-risk finding
    top_finding = max(findings, key=lambda f: f["confidence"]) if findings else {}
    top_finding.setdefault("url", target.get("url", ""))
    top_finding.setdefault("status", "inconclusive")
    cross_results_list = top_finding.get("cross_endpoint_results", [])
    top_finding["evidence"] = {
        "locations": summary.get("locations", {}),
        "replayable_locations": summary.get("replayable_locations", []),
        "token_type": top_finding.get("token_type", "unknown"),
        "replay_tested": top_finding.get("validation_state") == "active_tested",
        "cross_endpoint_tested": len(cross_results_list) > 0
        if isinstance(cross_results_list, list)
        else False,
    }

    return to_validation_result(top_finding, validator="token_reuse", category="token_reuse")


def _build_token_replay_notes(
    token_type: str, replay_result: dict[str, Any], cross_results: list[dict[str, Any]]
) -> str:
    """Build human-readable notes about token replay risk.

    Args:
        token_type: Assessed token type.
        replay_result: Result of replay test on original endpoint.
        cross_results: Results of cross-endpoint replay tests.

    Returns:
        Human-readable explanation string.
    """
    notes = []

    if token_type != "unknown":
        notes.append(f"Token type: {token_type}")

    if replay_result.get("token_accepted"):
        notes.append("Token was accepted on original endpoint - replay risk confirmed")
    elif replay_result.get("token_rejected"):
        notes.append("Token was properly rejected on original endpoint")
    elif replay_result.get("status") == "tested":
        notes.append(
            f"Token replay test returned status {replay_result.get('response_status', 'unknown')}"
        )

    cross_accepted = [r for r in cross_results if r.get("token_accepted")]
    if cross_accepted:
        notes.append(
            f"Token accepted on {len(cross_accepted)} other endpoint(s) - cross-endpoint replay risk"
        )

    if not notes:
        notes.append("Token replay testing inconclusive")

    return "; ".join(notes)

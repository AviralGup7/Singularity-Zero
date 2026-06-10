"""CORS misconfiguration validator (R7).

Detects permissive CORS policies that allow cross-origin script access to
sensitive data, including:
- Reflected origin (``Access-Control-Allow-Origin: <request origin>``).
- Wildcard origin with credentials allowed.
- Null origin allowed (``Access-Control-Allow-Origin: null``).

The validator runs in active mode when a target is in scope and in passive
mode otherwise. It does not require an out-of-band callback (R4-style).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from src.core.models import ValidationResult
from src.execution.validators.config.scoring_config import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
)
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.shared import (
    bounded_confidence,
    to_validation_result,
)

logger = logging.getLogger(__name__)

NULL_ORIGIN = "null"
ACA_HEADERS = "Access-Control-Allow-Headers"
ACA_CREDENTIALS = "Access-Control-Allow-Credentials"
ACA_METHODS = "Access-Control-Allow-Methods"
ACA_ORIGIN = "Access-Control-Allow-Origin"
ACA_EXPOSE_HEADERS = "Access-Control-Expose-Headers"

# Sensitive headers commonly leaked via Access-Control-Expose-Headers
SENSITIVE_EXPOSED_HEADERS = [
    "Authorization",
    "Set-Cookie",
    "X-Auth-Token",
    "X-CSRF-Token",
    "X-Session-ID",
    "X-API-Key",
    "X-Request-ID",
    "X-Amz-Request-Id",
    "WWW-Authenticate",
    "Token",
    "Refresh-Token",
]

# Additional origins to test for CORS reflection-based bypasses
#   - evil.example: standard reflected origin
#   - null: tests if null origin is accepted (iframe sandbox, data: URIs)
#   - https://null: tests URL-parsed "null" origin
#   - https://evil.example.com.attacker.com: subdomain confusable
#   - https://evil.example%2ecom@attacker.com: credential confusion
#   - https://evil.example.com%2eattacker.com: encoded dot bypass
#   - https://evil.example.com: attacker-controlled (modern CDN bypass)
#   - https://evil.example.com\t: tab character bypass
CORS_PROBE_ORIGINS: list[str] = [
    None,  # No origin (browser would not send Origin header naturally)
    "null",
    "https://null",
    "https://evil.example",
    "https://evil.example.com.attacker.com",
    "https://evil.example.com@attacker.com",
    "https://evil.example.com%2eattacker.com",
    "https://evil.example.com:443",
    "https://evil.example.com\t",  # tab character
    "null",  # test null origin specifically for sandbox iframes
]


def _normalize_origin(value: str) -> str:
    parsed = urlparse((value or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _is_null_origin(value: str) -> bool:
    return (value or "").strip().lower() == NULL_ORIGIN


def _is_wildcard(value: str) -> bool:
    return (value or "").strip() == "*"


def _is_any_origin_allowed(value: str) -> bool:
    """Check if any origin is accepted (wildcard or null-like patterns)."""
    v = (value or "").strip().lower()
    return v == "*" or v == "null" or v == "undefined" or v == "any"


def _has_sensitive_headers_exposed(response_headers: dict[str, str]) -> list[str]:
    """Check if sensitive headers are exposed via Access-Control-Expose-Headers."""
    headers_lower = {
        str(key).lower(): str(value) for key, value in (response_headers or {}).items()
    }
    expose_val = headers_lower.get(ACA_EXPOSE_HEADERS.lower(), "")
    if not expose_val:
        return []
    sensitive = {"set-cookie", "authorization", "x-api-key", "x-auth-token",
                 "x-csrftoken", "x-session-id", "x-access-token", "token",
                 "api-key", "secret", "private-token"}
    exposed = {h.strip().lower() for h in expose_val.split(",")}
    return sorted(sensitive & exposed)


def evaluate_cors(
    *,
    request_origin: str,
    response_headers: dict[str, str],
    scoring: ScoringConfig,
    in_scope: bool,
) -> dict[str, Any]:
    """Evaluate a single response for CORS misconfiguration.

    Args:
        request_origin: The ``Origin`` header value the validator sent.
        response_headers: The response headers observed.
        scoring: Per-validator ``ScoringConfig``.
        in_scope: Whether the target endpoint is in scope.

    Returns:
        A dict with signals, bonuses, status and confidence suitable for
        ``to_validation_result``.
    """
    headers_lower = {
        str(key).lower(): str(value) for key, value in (response_headers or {}).items()
    }
    allow_origin = headers_lower.get(ACA_ORIGIN.lower(), "")
    allow_credentials = headers_lower.get(ACA_CREDENTIALS.lower(), "").lower()
    allow_methods = headers_lower.get(ACA_METHODS.lower(), "")
    allow_headers = headers_lower.get(ACA_HEADERS.lower(), "")

    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []

    reflected = bool(
        request_origin
        and allow_origin
        and _normalize_origin(allow_origin) == _normalize_origin(request_origin)
    )
    null_allowed = _is_null_origin(allow_origin)
    wildcard_with_credentials = (
        _is_wildcard(allow_origin) and allow_credentials in {"true", "yes", "1"}
    )
    wildcard_with_state_changing_methods = (
        _is_wildcard(allow_origin)
        and any(
            method in allow_methods.upper()
            for method in ("PUT", "DELETE", "PATCH")
        )
    )

    # Detect sensitive headers exposed via Access-Control-Expose-Headers
    expose_headers_val = headers_lower.get(ACA_EXPOSE_HEADERS.lower(), "")
    sensitive_exposed = [
        h.strip() for h in expose_headers_val.split(",")
        if any(sh.lower() == h.strip().lower() for sh in SENSITIVE_EXPOSED_HEADERS)
    ]

    # Detect XSS via CORS reflected origin with credentials
    reflected_with_credentials = reflected and allow_credentials in {"true", "yes", "1"}

    if reflected:
        signals.append("reflected_origin")
        bonuses.append(0.12)
        notes.append("CORS reflects the request Origin header.")
    if reflected_with_credentials:
        signals.append("reflected_origin_with_credentials")
        bonuses.append(0.25)
        notes.append("CORS reflects the request Origin WITH credentials - critical data exfiltration risk.")
    if null_allowed:
        signals.append("null_origin_allowed")
        bonuses.append(0.18)
        notes.append("Access-Control-Allow-Origin: null accepted.")
    if wildcard_with_credentials:
        signals.append("wildcard_with_credentials")
        bonuses.append(0.20)
        notes.append("Wildcard origin combined with credentials is a critical risk.")
    if wildcard_with_state_changing_methods:
        signals.append("wildcard_with_state_changing_methods")
        bonuses.append(0.05)

    # Access-Control-Expose-Headers leaking sensitive headers
    if sensitive_exposed:
        signals.append("sensitive_headers_exposed")
        bonuses.append(0.10)
        notes.append(f"Access-Control-Expose-Headers leaks sensitive headers: {sensitive_exposed}")

    # Subdomain origin bypass: does the server reflect any subdomain of the target?
    if reflected:
        parsed_origin = urlparse(request_origin)
        parsed_allow = urlparse(allow_origin)
        if parsed_origin.hostname and parsed_allow.hostname:
            origin_domain = ".".join(parsed_origin.hostname.split(".")[-2:])
            allow_domain = ".".join(parsed_allow.hostname.split(".")[-2:])
            if origin_domain != allow_domain and parsed_allow.hostname.endswith(origin_domain):
                signals.append("subdomain_origin_bypass")
                bonuses.append(0.15)
                notes.append(f"Origin reflects a subdomain: {parsed_allow.hostname} vs {parsed_origin.hostname}")

    if signals and in_scope:
        if (
            reflected_with_credentials
            or null_allowed
            or wildcard_with_credentials
        ):
            status = ValidationStatus.CONFIRMED.value
        elif reflected or sensitive_exposed or wildcard_with_state_changing_methods:
            status = ValidationStatus.HEURISTIC.value
        else:
            status = ValidationStatus.HEURISTIC.value
    elif signals:
        status = ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    confidence = bounded_confidence(
        base=scoring.base,
        cap=scoring.cap,
        bonuses=bonuses,
    )
    evidence = {
        "request_origin": request_origin,
        "allow_origin": allow_origin,
        "allow_credentials": allow_credentials,
        "allow_methods": allow_methods,
        "allow_headers": allow_headers,
        "exposed_headers": expose_headers_val,
        "sensitive_exposed_headers": sensitive_exposed,
        "signals": signals,
        "notes": notes,
    }
    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "evidence": evidence,
        "bonuses": bonuses,
    }


def validate_cors_endpoint(
    *,
    target_url: str,
    request_origin: str,
    response_headers: dict[str, str],
    scoring: ScoringConfig,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Validate a single endpoint and return a result dict."""
    evaluation = evaluate_cors(
        request_origin=request_origin,
        response_headers=response_headers,
        scoring=scoring,
        in_scope=in_scope,
    )
    item = {
        "url": target_url,
        "status": evaluation["status"],
        "confidence": evaluation["confidence"],
        "in_scope": in_scope,
        "scope_reason": "scope_evaluated"
        if in_scope
        else "scope_unavailable_or_out_of_scope",
        "evidence": evaluation["evidence"],
    }
    return to_validation_result(
        item, validator="cors", category="cors_misconfiguration"
    ).__dict__


def validate(
    target: dict[str, Any], context: dict[str, Any]
) -> ValidationResult:
    """R1 facade entry point matching the ``Validator`` Protocol.

    The active probing is performed in the engine class
    (``CorsValidator``). This facade returns a passive evaluation that
    inspects any ``response_headers`` already present in ``context`` so
    callers using ``validate_target``/``validate_many`` get a CORS
    assessment without re-issuing HTTP requests.
    """
    target_url = str(target.get("url", ""))
    response_headers = dict(context.get("response_headers") or {})
    request_origin = str(context.get("cors_probe_origin") or build_cors_probe_origin(target_url))
    in_scope = bool(context.get("in_scope", True))
    scoring_name = "cors"
    scoring = DEFAULT_SCORING_CONFIG.get(scoring_name, ScoringConfig())
    if not response_headers:
        return ValidationResult(
            validator=scoring_name,
            category="cors_misconfiguration",
            url=target_url,
            status=ValidationStatus.INCONCLUSIVE.value,
            confidence=0.0,
            in_scope=in_scope,
            scope_reason="no_response_headers",
        )
    item = validate_cors_endpoint(
        target_url=target_url,
        request_origin=request_origin,
        response_headers=response_headers,
        scoring=scoring,
        in_scope=in_scope,
    )
    return ValidationResult(
        validator=scoring_name,
        category="cors_misconfiguration",
        url=item.get("url", target_url),
        status=item.get("status", ValidationStatus.INCONCLUSIVE.value),
        confidence=float(item.get("confidence", 0.0) or 0.0),
        in_scope=bool(item.get("in_scope", in_scope)),
        scope_reason=str(item.get("scope_reason", "scope_evaluated")),
        evidence=dict(item.get("evidence") or {}),
    )


def build_cors_probe_origin(target_url: str, *, override: str | None = None) -> str:
    """Build the Origin header value to use for the probe."""
    if override:
        return override
    parsed = urlparse(target_url or "")
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://evil.example"


def summarize_cors_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize a list of CORS findings."""
    if not findings:
        return {"status": "no_findings", "count": 0}
    reflected = sum(
        1
        for f in findings
        if "reflected_origin" in f.get("evidence", {}).get("signals", [])
    )
    reflected_with_creds = sum(
        1
        for f in findings
        if "reflected_origin_with_credentials" in f.get("evidence", {}).get("signals", [])
    )
    null_allowed = sum(
        1
        for f in findings
        if "null_origin_allowed" in f.get("evidence", {}).get("signals", [])
    )
    wildcard_creds = sum(
        1
        for f in findings
        if "wildcard_with_credentials" in f.get("evidence", {}).get("signals", [])
    )
    sensitive_exposed = sum(
        1
        for f in findings
        if "sensitive_headers_exposed" in f.get("evidence", {}).get("signals", [])
    )
    return {
        "status": "analyzed",
        "count": len(findings),
        "reflected_origin_count": reflected,
        "reflected_origin_with_credentials_count": reflected_with_creds,
        "null_origin_count": null_allowed,
        "wildcard_with_credentials_count": wildcard_creds,
        "sensitive_headers_exposed_count": sensitive_exposed,
    }

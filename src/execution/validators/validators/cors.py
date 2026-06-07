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


def _normalize_origin(value: str) -> str:
    parsed = urlparse((value or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _is_null_origin(value: str) -> bool:
    return (value or "").strip().lower() == NULL_ORIGIN


def _is_wildcard(value: str) -> bool:
    return (value or "").strip() == "*"


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

    if reflected:
        signals.append("reflected_origin")
        bonuses.append(0.12)
        notes.append("CORS reflects the request Origin header.")
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

    if signals and in_scope:
        if (
            reflected
            and (allow_credentials in {"true", "yes", "1"} or null_allowed)
        ) or null_allowed or wildcard_with_credentials:
            status = ValidationStatus.CONFIRMED.value
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
    return {
        "status": "analyzed",
        "count": len(findings),
        "reflected_origin_count": reflected,
        "null_origin_count": null_allowed,
        "wildcard_with_credentials_count": wildcard_creds,
    }

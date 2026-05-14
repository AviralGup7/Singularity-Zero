"""Mass assignment attack surface detector for OWASP API6: Mass Assignment.

Passively analyzes URLs and HTTP responses for endpoints that may be vulnerable
to mass assignment attacks, including JSON APIs accepting POST/PUT/PATCH with
sensitive field names, admin endpoints, and bulk update patterns.
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_noise_url,
    normalized_confidence,
)

_SENSITIVE_FIELD_NAMES = {
    "is_admin",
    "isadmin",
    "admin",
    "role",
    "roles",
    "permissions",
    "permission",
    "price",
    "prices",
    "balance",
    "balances",
    "status",
    "statuses",
    "is_verified",
    "isverified",
    "verified",
    "account_type",
    "accounttype",
    "user_type",
    "usertype",
    "privilege",
    "privileges",
    "access_level",
    "accesslevel",
    "is_active",
    "isactive",
    "active",
    "is_enabled",
    "isenabled",
    "enabled",
    "group",
    "groups",
    "department",
    "salary",
    "compensation",
    "bonus",
    "commission",
    "credit_limit",
    "creditlimit",
    "discount",
    "discount_rate",
    "tax_exempt",
    "taxexempt",
    "owner",
    "owner_id",
    "created_by",
    "createdby",
    "updated_by",
    "updatedby",
    "locked",
    "is_locked",
    "islocked",
    "banned",
    "is_banned",
    "isbanned",
    "suspended",
    "is_suspended",
    "issuspended",
    "flagged",
    "is_flagged",
    "isflagged",
    "moderator",
    "is_moderator",
    "ismoderator",
    "superuser",
    "is_superuser",
    "issuperuser",
    "staff",
    "is_staff",
    "isstaff",
    "level",
    "tier",
    "membership",
    "subscription",
    "plan",
}

_ADMIN_PATH_KEYWORDS = (
    "/admin",
    "/administrator",
    "/manage",
    "/management",
    "/control",
    "/panel",
    "/dashboard",
    "/console",
    "/superadmin",
    "/sysadmin",
    "/moderator",
    "/moderation",
    "/backoffice",
    "/back-office",
)

_BULK_PATH_KEYWORDS = (
    "/bulk",
    "/batch",
    "/mass",
    "/multi",
    "/batch-update",
    "/bulk-update",
    "/batch-delete",
    "/bulk-delete",
    "/import",
    "/export",
)

_OBJECT_CREATION_KEYWORDS = (
    "/create",
    "/new",
    "/add",
    "/insert",
    "/register",
    "/signup",
    "/onboard",
    "/provision",
    "/setup",
    "/initialize",
)

_UPDATE_PATH_KEYWORDS = (
    "/update",
    "/edit",
    "/modify",
    "/change",
    "/patch",
    "/put",
    "/save",
    "/set",
    "/configure",
    "/preferences",
    "/settings",
    "/profile/update",
    "/account/update",
)

_JSON_CONTENT_TYPES = (
    "application/json",
    "application/ld+json",
    "application/problem+json",
    "application/hal+json",
    "application/vnd.api+json",
    "text/json",
)

_SENSITIVE_FIELD_IN_BODY_RE = re.compile(
    r'"(?:is_admin|isadmin|admin|role|permissions|permission|price|balance|'
    r"status|is_verified|isverified|account_type|user_type|privilege|"
    r"access_level|is_active|is_enabled|enabled|group|salary|credit_limit|"
    r"discount|owner|locked|banned|suspended|superuser|is_superuser|"
    r'staff|is_staff|level|tier|plan)"\s*:',
    re.IGNORECASE,
)

_ADMIN_FIELD_PATTERN_RE = re.compile(
    r'"(?:is_admin|admin|role|privilege|access_level|superuser|is_superuser|'
    r'staff|is_staff|moderator|is_moderator)"\s*:\s*(?:true|"admin"|"superuser"|"moderator")',
    re.IGNORECASE,
)


def _check_url_mass_assignment_surface(url: str) -> list[str]:
    """Check URL patterns for mass assignment attack surface indicators."""
    signals: list[str] = []
    path = urlparse(url).path.lower()
    parsed = urlparse(url)

    is_json_api = "/api/" in path or path.endswith(".json") or classify_endpoint(url) == "API"

    is_mutating_method_path = any(
        kw in path for kw in _UPDATE_PATH_KEYWORDS + _OBJECT_CREATION_KEYWORDS + _BULK_PATH_KEYWORDS
    )

    if is_json_api and is_mutating_method_path:
        signals.append("json_api_mutating_endpoint")

    if any(kw in path for kw in _ADMIN_PATH_KEYWORDS):
        signals.append("admin_endpoint")

    if any(kw in path for kw in _BULK_PATH_KEYWORDS):
        signals.append("bulk_operation_endpoint")

    if any(kw in path for kw in _OBJECT_CREATION_KEYWORDS):
        signals.append("object_creation_endpoint")

    if any(kw in path for kw in _UPDATE_PATH_KEYWORDS):
        signals.append("update_endpoint")

    query_params = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    sensitive_params = query_params & _SENSITIVE_FIELD_NAMES
    if sensitive_params:
        signals.append(f"sensitive_query_params:{','.join(sorted(sensitive_params))}")

    return signals


def _check_response_body_fields(response: dict[str, Any]) -> list[str]:
    """Check response body for sensitive field names that shouldn't be client-controllable."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    if not body:
        return signals

    matches = _SENSITIVE_FIELD_IN_BODY_RE.findall(body)
    if matches:
        unique_fields = set()
        for match in matches[:10]:
            field = match.strip('"').lower().rstrip(":").strip()
            unique_fields.add(field)
        if unique_fields:
            signals.append(f"sensitive_fields_in_response:{','.join(sorted(unique_fields)[:8])}")

    admin_matches = _ADMIN_FIELD_PATTERN_RE.findall(body)
    if admin_matches:
        signals.append("admin_fields_in_response")

    return signals


def _check_content_type_json(response: dict[str, Any]) -> list[str]:
    """Check if response is JSON content type (indicating API endpoint)."""
    signals: list[str] = []
    content_type = str(response.get("content_type") or "").lower()
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    ct_header = headers.get("content-type", "").lower()

    combined = content_type or ct_header

    for json_ct in _JSON_CONTENT_TYPES:
        if json_ct in combined:
            signals.append("json_api_endpoint")
            break

    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "admin_fields_in_response",
        "admin_endpoint",
    }
    high_indicators = {
        "sensitive_fields_in_response:",
        "bulk_operation_endpoint",
        "sensitive_query_params:",
    }
    medium_indicators = {
        "json_api_mutating_endpoint",
        "object_creation_endpoint",
        "update_endpoint",
    }

    for signal in signals:
        if signal in critical_indicators:
            return "critical"
    for signal in signals:
        if signal in high_indicators or any(signal.startswith(ind) for ind in high_indicators):
            return "high"
    for signal in signals:
        if signal in medium_indicators or any(signal.startswith(ind) for ind in medium_indicators):
            return "medium"
    return "low"


def _calculate_risk_score(signals: list[str]) -> int:
    score = 0
    severity_scores: dict[str, int] = {
        "admin_fields_in_response": 10,
        "admin_endpoint": 8,
        "bulk_operation_endpoint": 7,
        "json_api_mutating_endpoint": 5,
        "object_creation_endpoint": 5,
        "update_endpoint": 4,
        "json_api_endpoint": 2,
    }

    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]
        elif signal.startswith("sensitive_fields_in_response:"):
            score += 6
        elif signal.startswith("sensitive_query_params:"):
            score += 5

    return min(score, 20)


def mass_assignment_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect mass assignment attack surfaces passively.

    Analyzes URLs and responses for:
    - JSON API endpoints accepting POST/PUT/PATCH mutations
    - Parameters suggesting sensitive fields (is_admin, role, permissions, price, etc.)
    - Response body field names that shouldn't be client-controllable
    - Admin-related endpoints with mutable operations
    - Bulk update endpoints accepting multiple object modifications
    - Object creation endpoints with many parameters

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of mass assignment findings sorted by risk score.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        signals = _check_url_mass_assignment_surface(url)
        if not signals:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.42,
            score=risk_score,
            signals=signals,
            cap=0.88,
        )

        title_parts: list[str] = []
        if "admin_endpoint" in signals:
            title_parts.append("Admin Endpoint with Mutation Surface")
        if "bulk_operation_endpoint" in signals:
            title_parts.append("Bulk Operation Endpoint")
        if "object_creation_endpoint" in signals:
            title_parts.append("Object Creation Endpoint")
        if "update_endpoint" in signals:
            title_parts.append("Update Endpoint")
        if "json_api_mutating_endpoint" in signals:
            title_parts.append("JSON API Mutating Endpoint")
        if any(s.startswith("sensitive_query_params:") for s in signals):
            title_parts.append("Sensitive Query Parameters")

        title = "; ".join(title_parts) if title_parts else "Mass Assignment Surface Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        signals: list[str] = []
        signals.extend(_check_content_type_json(response))
        signals.extend(_check_response_body_fields(response))

        if not signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(signals)
        risk_score = _calculate_risk_score(signals)
        confidence = normalized_confidence(
            base=0.42,
            score=risk_score,
            signals=signals,
            cap=0.90,
        )

        title_parts: list[str] = []
        if "admin_fields_in_response" in signals:
            title_parts.append("Admin Fields Exposed in Response")
        if any(s.startswith("sensitive_fields_in_response:") for s in signals):
            title_parts.append("Sensitive Fields in Response Body")
        if "json_api_endpoint" in signals:
            title_parts.append("JSON API Endpoint Identified")

        title = "; ".join(title_parts) if title_parts else "Mass Assignment Response Indicator"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]

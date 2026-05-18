"""Mass Assignment Detector (Active).

Tests POST/PUT endpoints for mass assignment vulnerabilities by injecting
sensitive fields into request bodies and comparing responses for unexpected
acceptance or behavioral changes.
"""

import json
import logging
from typing import Any
from urllib.parse import urlparse

import requests

from src.analysis.helpers import (
    build_endpoint_meta,
    endpoint_base_key,
    normalize_headers,
)
from src.analysis.helpers.scoring import normalized_confidence
from src.core.utils.url_validation import is_safe_url

logger = logging.getLogger(__name__)

CHECK_SPEC = {
    "key": "mass_assignment_detector",
    "label": "Mass Assignment Detector",
    "description": "Actively test POST/PUT endpoints for mass assignment vulnerabilities by injecting sensitive fields into JSON request bodies and comparing responses.",
    "group": "active",
    "input_kind": "priority_urls_and_cache",
}

ADMIN_FIELDS = [
    {"is_admin": True},
    {"role": "admin"},
    {"permissions": ["admin"]},
    {"account_type": "premium"},
    {"is_superuser": True},
    {"admin": True},
    {"user_type": "admin"},
    {"access_level": "admin"},
    {"privilege": "admin"},
    {"is_staff": True},
]

FINANCIAL_FIELDS = [
    {"balance": 999999},
    {"discount": 100},
    {"price": 0.01},
    {"amount": 0},
    {"credit": 999999},
    {"wallet_balance": 999999},
    {"total": 0.01},
    {"cost": 0},
    {"fee": 0},
    {"salary": 999999},
]

STATE_FIELDS = [
    {"approved": True},
    {"status": "verified"},
    {"email_verified": True},
    {"override": True},
    {"internal_note": "test"},
    {"verified": True},
    {"is_verified": True},
    {"confirmed": True},
    {"active": True},
    {"enabled": True},
    {"locked": False},
    {"suspended": False},
    {"banned": False},
    {"deleted": False},
    {"flagged": False},
    {"moderated": True},
]

SENSITIVE_FIELDS = [
    {"password": "test123"},
    {"password_confirmation": "test123"},
    {"secret": "test"},
    {"api_key": "test_key_12345"},
    {"token": "test_token"},
    {"role_id": 1},
    {"group_id": 1},
    {"organization_id": 1},
    {"tenant_id": 1},
    {"created_by": "admin"},
    {"updated_by": "admin"},
    {"owner": "admin"},
    {"creator": "admin"},
    {"last_modified_by": "admin"},
]

ALL_TEST_PAYLOADS = (
    [("admin", field, "high") for field in ADMIN_FIELDS]
    + [("financial", field, "medium") for field in FINANCIAL_FIELDS]
    + [("state", field, "medium") for field in STATE_FIELDS]
    + [("sensitive", field, "low") for field in SENSITIVE_FIELDS]
)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"

JSON_CONTENT_TYPES = (
    "application/json",
    "application/ld+json",
    "application/problem+json",
    "text/json",
)


def _is_json_endpoint(url: str, response: dict[str, Any] | None = None) -> bool:
    """Check if a URL/response appears to be a JSON API endpoint."""
    if response:
        headers = normalize_headers(response)
        content_type = headers.get("content-type", "").lower()
        if any(token in content_type for token in JSON_CONTENT_TYPES):
            return True
        body = response.get("body_text") or response.get("body") or ""
        if body:
            stripped = body.strip()
            if stripped.startswith(("{", "[")):
                try:
                    json.loads(stripped[:50000])
                    return True
                except (json.JSONDecodeError, ValueError):
                    pass
    path = urlparse(url).path.lower()
    if any(token in path for token in ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/")):
        return True
    if path.endswith((".json", "/")):
        return True
    return False


def _safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Make a safe HTTP request and return response info."""
    req_headers = dict(headers or {})
    req_headers.setdefault("User-Agent", USER_AGENT)
    req_headers.setdefault("Accept", "application/json, text/plain, */*")
    if not is_safe_url(url):
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": "URL failed safety check",
        }
    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": resp_body[:5000],
            "body_length": len(resp_body),
            "success": resp.status_code < 400,
        }
    except requests.RequestException as e:
        resp_body = ""
        resp_obj = getattr(e, "response", None)
        status = 0
        headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                headers = dict(resp_obj.headers)
            except Exception:  # noqa: S110
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:5000],
            "body_length": len(resp_body or ""),
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": str(e),
        }


def _compute_body_similarity(original: str, mutated: str) -> float:
    """Compute similarity ratio between two response bodies."""
    if not original and not mutated:
        return 1.0
    if not original or not mutated:
        return 0.0
    if original == mutated:
        return 1.0
    orig_len = len(original)
    mut_len = len(mutated)
    max_len = max(orig_len, mut_len)
    if max_len == 0:
        return 1.0
    common = 0
    min_len = min(orig_len, mut_len)
    for i in range(min_len):
        if original[i] == mutated[i]:
            common += 1
    return common / max_len


def _build_finding(
    url: str,
    status_code: int | None,
    category: str,
    title: str,
    severity: str,
    confidence: float,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
) -> dict[str, Any]:
    """Build a standardized finding dictionary."""
    meta = build_endpoint_meta(url)
    score_map = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}
    score = score_map.get(severity, 20)
    return {
        "url": url,
        "endpoint_key": meta["endpoint_key"],
        "endpoint_base_key": meta["endpoint_base_key"],
        "endpoint_type": meta["endpoint_type"],
        "status_code": status_code,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": round(confidence, 2),
        "score": score,
        "signals": sorted(set(signals)),
        "evidence": evidence,
        "explanation": explanation,
    }


def mass_assignment_detector(
    priority_urls: list[dict[str, Any]] | None = None,
    response_cache: Any = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Test POST/PUT endpoints for mass assignment vulnerabilities.

    For each identified JSON API endpoint, sends requests with sensitive
    fields injected into the body and compares responses to detect whether
    the fields were accepted and processed.

    Args:
        priority_urls: List of URL dicts with endpoint information.
        response_cache: Response cache for retrieving original responses.
        limit: Maximum number of endpoints to test.

    Returns:
        List of finding dictionaries for endpoints that accepted mass assignment.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    if not priority_urls:
        return findings

    endpoints_to_test: list[dict[str, Any]] = []
    for item in priority_urls[: limit * 2]:
        url = str(item.get("url", "")).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue
        resp = None
        if response_cache is not None:
            try:
                resp = response_cache.get(url)
            except Exception:  # noqa: S110
                pass
        if not _is_json_endpoint(url, resp):
            continue
        endpoints_to_test.append({"url": url, "response": resp})
        if len(endpoints_to_test) >= limit:
            break

    for endpoint in endpoints_to_test:
        url = endpoint["url"]
        original_resp = endpoint.get("response")

        base_key = endpoint_base_key(url)
        if base_key in seen:
            continue
        seen.add(base_key)

        original_body = ""
        original_status = 0
        original_headers: dict[str, str] = {}

        if original_resp:
            original_body = original_resp.get("body_text") or original_resp.get("body") or ""
            original_status = original_resp.get("status_code") or 0
            original_headers = normalize_headers(original_resp)

        if not original_body and original_status == 0:
            baseline = _safe_request(url, method="GET", timeout=8)
            original_status = baseline.get("status", 0)
            original_body = baseline.get("body", "")
            original_headers = baseline.get("headers", {})

        if original_status in (404, 405, 410, 503):
            continue

        original_json: dict[str, Any] | list[Any] | None = None
        stripped = original_body.strip()
        if stripped.startswith(("{", "[")):
            try:
                original_json = json.loads(stripped[:50000])
            except (json.JSONDecodeError, ValueError):
                pass

        request_body = {}
        if isinstance(original_json, dict):
            request_body = dict(original_json)
        elif (
            isinstance(original_json, list)
            and len(original_json) > 0
            and isinstance(original_json[0], dict)
        ):
            request_body = dict(original_json[0])
        else:
            request_body = {"test": "value"}

        request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        for key, val in original_headers.items():
            if key.lower() in ("authorization", "cookie", "x-csrf-token", "x-requested-with"):
                request_headers[key] = val

        accepted_fields: list[dict[str, Any]] = []
        field_categories: set[str] = set()

        for category_name, test_field, field_severity in ALL_TEST_PAYLOADS:
            mutated_body = dict(request_body)
            tf: dict[str, object] = test_field if isinstance(test_field, dict) else {}
            mutated_body.update(tf)

            try:
                body_bytes = json.dumps(mutated_body).encode("utf-8")
            except (TypeError, ValueError) as exc:
                logger.debug("Ignored: %s", exc)
                continue

            mutation_result = _safe_request(
                url,
                method="POST",
                headers=request_headers,
                body=body_bytes,
                timeout=10,
            )

            mutation_status = mutation_result.get("status", 0)
            mutation_body = mutation_result.get("body", "")
            mutation_body_length = mutation_result.get("body_length", 0)
            original_body_length = len(original_body)

            field_accepted = False
            acceptance_signals: list[str] = []

            if mutation_status == 200 and original_status not in (200, 0):
                field_accepted = True
                acceptance_signals.append("status_changed_to_200")

            if mutation_status == 200 and original_status in (400, 403, 401):
                field_accepted = True
                acceptance_signals.append("bypassed_error_status")

            if mutation_status == original_status and mutation_status in (200, 201, 204):
                if original_body_length > 0 and mutation_body_length > 0:
                    similarity = _compute_body_similarity(original_body, mutation_body)
                    length_diff = abs(mutation_body_length - original_body_length)
                    length_pct = (
                        (length_diff / original_body_length * 100)
                        if original_body_length > 0
                        else 0
                    )
                    if length_pct > 20:
                        field_accepted = True
                        acceptance_signals.append(f"body_length_changed_{length_pct:.0f}%")
                    if similarity < 0.8:
                        field_accepted = True
                        acceptance_signals.append(f"body_similarity_{similarity:.2f}")
                    if similarity >= 0.8 and length_pct <= 20:
                        field_accepted = True
                        acceptance_signals.append("field_accepted_without_error")
                else:
                    field_accepted = True
                    acceptance_signals.append("no_error_response")

            if mutation_status in (200, 201, 204, 202):
                if mutation_body:
                    try:
                        resp_json = json.loads(mutation_body[:50000])
                        if isinstance(resp_json, dict):
                            for injected_key in tf:
                                if injected_key in resp_json:
                                    field_accepted = True
                                    acceptance_signals.append(f"field_reflected:{injected_key}")
                    except (json.JSONDecodeError, ValueError):
                        pass

            if field_accepted:
                accepted_fields.append(
                    {
                        "category": category_name,
                        "field": list(tf.keys())[0],
                        "value": list(tf.values())[0],
                        "status_code": mutation_status,
                        "signals": acceptance_signals,
                        "severity": field_severity,
                    }
                )
                field_categories.add(category_name)

        if not accepted_fields:
            continue

        highest_severity = "low"
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for af in accepted_fields:
            if severity_order.get(af["severity"], 4) < severity_order.get(highest_severity, 4):
                highest_severity = af["severity"]

        admin_accepted = any(af["category"] == "admin" for af in accepted_fields)
        financial_accepted = any(af["category"] == "financial" for af in accepted_fields)
        state_accepted = any(af["category"] == "state" for af in accepted_fields)
        sensitive_accepted = any(af["category"] == "sensitive" for af in accepted_fields)

        if admin_accepted:
            highest_severity = "high"
        elif financial_accepted and highest_severity == "low":
            highest_severity = "medium"

        signals = []
        if admin_accepted:
            signals.append("admin_fields_accepted")
        if financial_accepted:
            signals.append("financial_fields_accepted")
        if state_accepted:
            signals.append("state_fields_accepted")
        if sensitive_accepted:
            signals.append("sensitive_fields_accepted")
        for af in accepted_fields[:10]:
            signals.extend(af["signals"])

        evidence = {
            "accepted_fields": accepted_fields[:15],
            "total_fields_tested": len(ALL_TEST_PAYLOADS),
            "categories_affected": sorted(field_categories),
            "original_status": original_status if original_status else None,
            "request_body_sample": {k: str(v)[:100] for k, v in list(request_body.items())[:5]},
        }

        title = f"Mass assignment: {len(accepted_fields)} field(s) accepted"
        if admin_accepted:
            title = f"Mass assignment: admin/role fields accepted ({len(accepted_fields)} total)"
        elif financial_accepted:
            title = f"Mass assignment: financial fields accepted ({len(accepted_fields)} total)"

        confidence = normalized_confidence(
            base=0.50
            if highest_severity == "low"
            else 0.65
            if highest_severity == "medium"
            else 0.80,
            score=8 if highest_severity == "high" else 5 if highest_severity == "medium" else 2,
            signals=signals,
        )

        explanation = (
            f"Endpoint accepted {len(accepted_fields)} out of {len(ALL_TEST_PAYLOADS)} injected fields. "
            f"Categories: {', '.join(sorted(field_categories))}. "
            f"Admin fields: {admin_accepted}, Financial: {financial_accepted}, "
            f"State: {state_accepted}, Sensitive: {sensitive_accepted}. "
            f"Original status: {original_status}. "
            f"This suggests insufficient input validation on the server side."
        )

        findings.append(
            _build_finding(
                url=url,
                status_code=original_status if original_status else None,
                category="mass_assignment",
                title=title,
                severity=highest_severity,
                confidence=confidence,
                signals=signals,
                evidence=evidence,
                explanation=explanation,
            )
        )

    findings.sort(
        key=lambda f: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5),
            -f["confidence"],
            f["url"],
        )
    )

    return findings[:limit]

"""Email Header Injection Probe (Active).

Tests email-related parameters for CRLF injection vulnerabilities that could
allow attackers to inject arbitrary email headers (Cc, Bcc, Subject, etc.)
into outbound emails, potentially leading to email spoofing, information
leakage, or stored XSS via email clients.

The probe identifies endpoints with email-related parameters, sends crafted
CRLF injection payloads, and analyzes responses for indicators of successful
header injection including reflected header values, status code changes,
mail backend errors, and parameter reflection without sanitization.

Usage:
    from src.analysis.checks.active.email_header_injection import email_header_injection_probe

    findings = email_header_injection_probe(priority_urls, response_cache, limit=10)
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import requests

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.core.utils.url_validation import is_safe_url

__all__ = ["email_header_injection_probe", "EMAIL_HEADER_INJECTION_SPEC"]

EMAIL_HEADER_INJECTION_SPEC = {
    "key": "email_header_injection_probe",
    "label": "Email Header Injection Probe",
    "description": "Test email-related parameters for CRLF injection vulnerabilities that could allow header injection into outbound emails.",
    "group": "active",
    "slug": "email_header_injection",
    "enabled_by_default": True,
}

EMAIL_PARAM_NAMES = frozenset(
    {
        "to",
        "from",
        "subject",
        "reply_to",
        "reply-to",
        "cc",
        "bcc",
        "email",
        "recipient",
        "sender",
        "mail",
        "contact",
        "message",
        "feedback",
        "subscribe",
        "newsletter",
        "invite",
        "invitation",
        "notify",
        "notification",
    }
)

CRLF_INJECTION_PAYLOADS = [
    (
        "crlf_cc_injection",
        "test%0d%0aCc:%20victim@evil.com",
        "Cc: victim@evil.com",
    ),
    (
        "crlf_bcc_injection",
        "test%0d%0aBcc:%20victim@evil.com",
        "Bcc: victim@evil.com",
    ),
    (
        "crlf_subject_injection",
        "test%0d%0aSubject:%20Injected%20Subject",
        "Subject: Injected Subject",
    ),
    (
        "crlf_xss_injection",
        "test%0d%0a%0d%0a<script>alert(1)</script>",
        "<script>alert(1)</script>",
    ),
    (
        "crlf_custom_header",
        "test%0d%0aX-Injected-Header:%20true",
        "X-Injected-Header: true",
    ),
    (
        "crlf_content_type",
        "test%0d%0aContent-Type:%20text/html",
        "Content-Type: text/html",
    ),
    (
        "crlf_reply_to",
        "test%0d%0aReply-To:%20attacker@evil.com",
        "Reply-To: attacker@evil.com",
    ),
    (
        "crlf_mime_version",
        "test%0d%0aMIME-Version:%201.0",
        "MIME-Version: 1.0",
    ),
    (
        "lf_only_cc",
        "test%0aCc:%20victim@evil.com",
        "Cc: victim@evil.com",
    ),
    (
        "cr_only_cc",
        "test%0dCc:%20victim@evil.com",
        "Cc: victim@evil.com",
    ),
    (
        "encoded_crlf_cc",
        "test%250d%250aCc:%20victim@evil.com",
        "Cc: victim@evil.com",
    ),
    (
        "unicode_crlf_cc",
        "test\u000d\u000aCc: victim@evil.com",
        "Cc: victim@evil.com",
    ),
]

MAIL_BACKEND_ERROR_RE = re.compile(
    r"(?i)(?:postfix|sendmail|exim|qmail|smtp|mail\s*server|"
    r"mail\s*transport|mta|email\s*delivery|mail\s*daemon|"
    r"smtp\s*error|mail\s*error|550\s|553\s|554\s|"
    r"relay\s*access\s*denied|mailbox\s*unavailable|"
    r"invalid\s*recipient|unknown\s*user|user\s*not\s*found|"
    r"mail\s*from\s*rejected|sender\s*rejected)"
)

INJECTED_HEADER_REFLECTION_RE = re.compile(
    r"(?i)(?:Cc:|Bcc:|Subject:|Reply-To:|X-Injected-Header:|"
    r"Content-Type:\s*text/html|MIME-Version:)",
)

XSS_PATTERN_IN_BODY = re.compile(r"<script>alert\(1\)</script>", re.IGNORECASE)

EMAIL_REFLECTION_RE = re.compile(
    r"(?i)(?:victim@evil\.com|attacker@evil\.com|"
    r"injected\s*subject|injected\s*header)",
)


def _safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    req_headers = dict(headers or {})
    req_headers.setdefault(
        "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"
    )
    req_headers.setdefault("Accept", "*/*")
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
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": (resp.text or "")[:5000],
            "success": resp.status_code < 400,
        }
    except requests.RequestException as e:
        resp_obj = getattr(e, "response", None)
        resp_body = ""
        status = 0
        headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                headers = dict(resp_obj.headers)
            except Exception:
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:5000],
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "success": False,
            "error": str(e),
        }


def _normalize_headers(raw_headers: dict[str, Any] | None) -> dict[str, str]:
    """Normalize response headers to lowercase keys with string values."""
    if not raw_headers:
        return {}
    return {str(k).lower(): str(v) for k, v in raw_headers.items()}


def _severity_score(severity: str) -> int:
    """Map a severity string to a numeric score.

    Args:
        severity: Severity level string.

    Returns:
        Numeric score (0-100).
    """
    mapping = {
        "critical": 100,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10,
    }
    return mapping.get(severity.lower(), 10)


def _compute_confidence(issues: list[str]) -> float:
    """Compute confidence score from detected issues.

    Args:
        issues: List of issue identifiers.

    Returns:
        Confidence between 0.0 and 1.0.
    """
    if not issues:
        return 0.3
    confidence_map = {
        "header_injection_confirmed": 0.95,
        "xss_via_email_header": 0.92,
        "crlf_accepted_email_param": 0.85,
        "mail_backend_error": 0.75,
        "email_param_reflection": 0.70,
        "status_code_change": 0.65,
        "email_param_no_validation": 0.50,
        "encoded_crlf_accepted": 0.80,
    }
    max_conf = max((confidence_map.get(issue, 0.4) for issue in issues), default=0.3)
    bonus = min(0.05, len(issues) * 0.01)
    return round(min(max_conf + bonus, 0.98), 2)


def _determine_severity(issues: list[str]) -> str:
    """Determine the highest severity from detected issues.

    Args:
        issues: List of issue identifiers.

    Returns:
        Severity string.
    """
    severity_map = {
        "header_injection_confirmed": "high",
        "xss_via_email_header": "high",
        "crlf_accepted_email_param": "medium",
        "mail_backend_error": "medium",
        "email_param_reflection": "low",
        "status_code_change": "medium",
        "email_param_no_validation": "low",
        "encoded_crlf_accepted": "medium",
    }
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    if not issues:
        return "low"
    return max(
        issues,
        key=lambda i: severity_order.get(severity_map.get(i, "low"), 0),
    )


def email_header_injection_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any | None = None,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test email-related parameters for CRLF injection vulnerabilities.

    Identifies endpoints with email-related parameters (to, from, subject,
    reply_to, cc, bcc, email, etc.) and sends crafted CRLF injection payloads
    to test whether the application properly sanitizes input before using it
    in email headers.

    Detection indicators include:
    - Reflected injected header values in the response body
    - HTTP status code changes between baseline and probe requests
    - Mail backend error messages (Postfix, Sendmail, SMTP errors)
    - XSS payloads reflected without sanitization
    - Email parameters accepted without any input validation

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Optional response cache for making requests. If None,
            uses direct HTTP requests via _safe_request.
        limit: Maximum number of findings to return.

    Returns:
        List of email header injection findings sorted by confidence.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        email_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in EMAIL_PARAM_NAMES
        ]
        if not email_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, param_value in email_params:
            if len(url_probes) >= 3:
                break

            baseline_resp = None
            if response_cache is not None:
                try:
                    baseline_resp = response_cache.request(
                        url,
                        headers={"Cache-Control": "no-cache", "X-Email-Probe": "baseline"},
                    )
                except Exception:
                    baseline_resp = None
            if baseline_resp is None:
                baseline_resp = _safe_request(url)

            baseline_status = int(
                baseline_resp.get("status") or baseline_resp.get("status_code") or 0
            )

            for payload_name, payload_value, expected_header in CRLF_INJECTION_PAYLOADS:
                if len(url_probes) >= 3:
                    break

                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

                probe_resp = None
                if response_cache is not None:
                    try:
                        probe_resp = response_cache.request(
                            test_url,
                            headers={"Cache-Control": "no-cache", "X-Email-Probe": payload_name},
                        )
                    except Exception:
                        probe_resp = None
                if probe_resp is None:
                    probe_resp = _safe_request(test_url)

                body = str(probe_resp.get("body") or probe_resp.get("body_text") or "")[:5000]
                status = int(probe_resp.get("status") or probe_resp.get("status_code") or 0)
                resp_headers = _normalize_headers(probe_resp.get("headers"))

                issues_for_hit: list[str] = []

                if INJECTED_HEADER_REFLECTION_RE.search(body):
                    issues_for_hit.append("header_injection_confirmed")

                if XSS_PATTERN_IN_BODY.search(body):
                    issues_for_hit.append("xss_via_email_header")

                if expected_header.lower() in body.lower() and param_name.lower() in body.lower():
                    if "header_injection_confirmed" not in issues_for_hit:
                        issues_for_hit.append("crlf_accepted_email_param")

                if EMAIL_REFLECTION_RE.search(body):
                    if "crlf_accepted_email_param" not in issues_for_hit:
                        issues_for_hit.append("crlf_accepted_email_param")

                if MAIL_BACKEND_ERROR_RE.search(body):
                    issues_for_hit.append("mail_backend_error")

                if baseline_status > 0 and status > 0:
                    if (baseline_status < 400 and status >= 400) or (
                        baseline_status >= 400 and status < 400
                    ):
                        issues_for_hit.append("status_code_change")

                if resp_headers.get("x-injected-header") == "true":
                    if "header_injection_confirmed" not in issues_for_hit:
                        issues_for_hit.append("header_injection_confirmed")

                if (
                    resp_headers.get("set-cookie")
                    and "victim@evil.com" in resp_headers.get("set-cookie", "").lower()
                ):
                    if "header_injection_confirmed" not in issues_for_hit:
                        issues_for_hit.append("header_injection_confirmed")

                if "%0d%0a" in body.lower() or "\\r\\n" in body.lower():
                    if not issues_for_hit:
                        issues_for_hit.append("encoded_crlf_accepted")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "original_value": param_value[:80],
                            "payload_type": payload_name,
                            "payload_preview": payload_value[:80],
                            "expected_header": expected_header,
                            "status_code": status,
                            "baseline_status": baseline_status,
                            "issues": sorted(set(issues_for_hit)),
                        }
                    )
                    break

        if not url_probes:
            for idx, param_name, param_value in email_params:
                if len(url_probes) >= 2:
                    break
                updated = list(query_pairs)
                updated[idx] = (param_name, "<script>alert(1)</script>")
                test_url = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

                probe_resp = None
                if response_cache is not None:
                    try:
                        probe_resp = response_cache.request(
                            test_url,
                            headers={
                                "Cache-Control": "no-cache",
                                "X-Email-Probe": "reflection-test",
                            },
                        )
                    except Exception:
                        probe_resp = None
                if probe_resp is None:
                    probe_resp = _safe_request(test_url)

                body = str(probe_resp.get("body") or probe_resp.get("body_text") or "")[:5000]
                status = int(probe_resp.get("status") or probe_resp.get("status_code") or 0)

                if "<script>alert(1)</script>" in body:
                    url_issues.append("email_param_reflection")
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "payload_type": "xss_reflection_test",
                            "status_code": status,
                            "issues": ["email_param_reflection"],
                        }
                    )
                elif "<script>" in body.lower() and "alert" in body.lower():
                    url_issues.append("email_param_reflection")
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "payload_type": "xss_reflection_test",
                            "status_code": status,
                            "issues": ["email_param_reflection"],
                        }
                    )

        if not url_probes and email_params:
            url_issues.append("email_param_no_validation")
            for idx, param_name, param_value in email_params[:2]:
                url_probes.append(
                    {
                        "parameter": param_name,
                        "payload_type": "no_validation_detected",
                        "issues": ["email_param_no_validation"],
                    }
                )

        if url_probes:
            severity = _determine_severity(url_issues)
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "status_code": int(url_probes[0].get("status_code") or 0)
                    if url_probes
                    else None,
                    "category": "email_header_injection",
                    "title": f"Email Header Injection in '{', '.join(p['parameter'] for p in url_probes[:3])}' parameter(s)",
                    "severity": severity,
                    "confidence": _compute_confidence(url_issues),
                    "score": _severity_score(severity),
                    "signals": sorted(set(url_issues)),
                    "evidence": {
                        "email_parameters": [p["parameter"] for p in url_probes],
                        "probes": url_probes[:5],
                        "payload_count": len(CRLF_INJECTION_PAYLOADS),
                        "tested_params_count": len(email_params),
                    },
                    "explanation": (
                        f"The endpoint accepts email-related parameters ({', '.join(str(p[1]) for p in email_params[:3])}) "
                        f"that may be vulnerable to CRLF injection. "
                        f"Tested {len(CRLF_INJECTION_PAYLOADS)} payloads targeting email header injection. "
                        f"Detected indicators: {', '.join(sorted(set(url_issues)))}. "
                        f"Email parameters should be strictly validated and sanitized before use in mail functions."
                    ),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]

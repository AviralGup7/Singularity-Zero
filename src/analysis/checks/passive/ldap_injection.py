"""LDAP Injection Surface Analyzer (Passive).

Analyzes HTTP responses and URLs for LDAP injection surface indicators,
including LDAP-related parameters, error messages, authentication endpoints,
and filter injection patterns.
"""

import logging
import re
from typing import Any

from src.analysis.helpers import (
    build_endpoint_meta,
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    meaningful_query_pairs,
)
from src.analysis.helpers.scoring import normalized_confidence

logger = logging.getLogger(__name__)

CHECK_SPEC = {
    "key": "ldap_injection_surface_analyzer",
    "label": "LDAP Injection Surface Analyzer",
    "description": "Detect LDAP injection surface indicators in URLs and response bodies, including LDAP parameters, error messages, and authentication endpoints.",
    "group": "passive",
    "input_kind": "urls_and_responses",
}

LDAP_PARAM_NAMES = frozenset(
    {
        "uid",
        "cn",
        "dn",
        "samaccountname",
        "userprincipalname",
        "mail",
        "givenname",
        "sn",
        "objectclass",
        "memberof",
        "searchfilter",
        "ldap",
        "directory",
        "bind",
        "basedn",
        "searchbase",
        "filter",
        "scope",
        "deref",
        "sizelimit",
        "timelimit",
        "attrs",
        "attributes",
        "manager",
        "ou",
        "dc",
        "rdn",
        "principal",
        "kerberos",
        "ntlm",
        "ad",
        "activedirectory",
        "userdn",
        "groupdn",
        "ldapfilter",
        "queryfilter",
        "authdn",
        "binddn",
        "bindpw",
        "rootdn",
        "suffix",
    }
)

LDAP_ERROR_PATTERNS = [
    re.compile(r"LDAP\s*error", re.IGNORECASE),
    re.compile(r"javax\.naming", re.IGNORECASE),
    re.compile(r"ldap_bind", re.IGNORECASE),
    re.compile(r"Active\s*Directory", re.IGNORECASE),
    re.compile(r"Novell\s*eDirectory", re.IGNORECASE),
    re.compile(r"OpenLDAP", re.IGNORECASE),
    re.compile(r"ldaps?://", re.IGNORECASE),
    re.compile(r"LDAP\s*operations?\s*error", re.IGNORECASE),
    re.compile(r"invalid\s*DN\s*syntax", re.IGNORECASE),
    re.compile(r"unwilling\s*to\s*perform", re.IGNORECASE),
    re.compile(r"constraint\s*violation", re.IGNORECASE),
    re.compile(r"LDAPResultCode", re.IGNORECASE),
    re.compile(r"LDAPException", re.IGNORECASE),
    re.compile(r"NamingException", re.IGNORECASE),
    re.compile(r"CommunicationException.*LDAP", re.IGNORECASE),
    re.compile(r"AuthenticationException.*LDAP", re.IGNORECASE),
    re.compile(r"InvalidCredentialsException", re.IGNORECASE),
    re.compile(r"SizeLimitExceededException", re.IGNORECASE),
    re.compile(r"TimeLimitExceededException", re.IGNORECASE),
    re.compile(r"ReferralException", re.IGNORECASE),
    re.compile(r"ldap_search", re.IGNORECASE),
    re.compile(r"ldap_compare", re.IGNORECASE),
    re.compile(r"ldap_modify", re.IGNORECASE),
    re.compile(r"ldap_add", re.IGNORECASE),
    re.compile(r"ldap_delete", re.IGNORECASE),
    re.compile(r"3260", re.IGNORECASE),
    re.compile(r"Global\s*Catalog", re.IGNORECASE),
    re.compile(r"error\s*code\s*[:\s]*[0-9]+.*LDAP", re.IGNORECASE),
    re.compile(r"LDAP:\s*0x[0-9a-fA-F]+", re.IGNORECASE),
]

LDAP_AUTH_PATH_HINTS = frozenset(
    {
        "/ldap",
        "/auth",
        "/login",
        "/directory",
        "/ad",
        "/sso",
        "/saml",
        "/authenticate",
        "/signin",
        "/identity",
        "/kerberos",
        "/ntlm",
        "/windowsauth",
        "/activedirectory",
        "/userdir",
        "/userdirectory",
        "/globalcatalog",
        "/ldapsync",
        "/ldapauth",
        "/ldaplogin",
    }
)

LDAP_FILTER_CHARS = frozenset({"(", ")", "*", "|", "&", "!"})

LDAP_FILTER_INJECTION_RE = re.compile(
    r"[\(\)\*\|\&!]{2,}"
    r"|"
    r"\(\s*[a-zA-Z]+\s*="
    r"|"
    r"\(\s*\|\s*\("
    r"|"
    r"\(\s*&\s*\("
    r"|"
    r"\*\s*\)"
    r"|"
    r"\(\s*!\s*\(",
    re.IGNORECASE,
)

LDAP_SEVERITY_CONTEXT = {
    "admin": "high",
    "role": "high",
    "permission": "high",
    "is_admin": "high",
    "privilege": "high",
    "financial": "medium",
    "money": "medium",
    "price": "medium",
    "balance": "medium",
    "discount": "medium",
    "generic": "low",
}


def _detect_ldap_params_in_url(url: str) -> list[str]:
    """Extract LDAP-related parameter names from URL query string."""
    found = []
    try:
        pairs = meaningful_query_pairs(url)
        for name, _value in pairs:
            if name.lower() in LDAP_PARAM_NAMES:
                found.append(name.lower())
    except Exception as exc:
        logger.warning("LDAP param detection failed for %s: %s", url, exc)
    return found


def _detect_ldap_filter_injection_in_url(url: str) -> list[str]:
    """Detect LDAP filter injection characters in URL parameter values."""
    signals: list[str] = []
    try:
        from urllib.parse import parse_qs, unquote, urlparse

        query = urlparse(url).query
        if not query:
            return signals
        params = parse_qs(query, keep_blank_values=True)
        for name, values in params.items():
            for value in values:
                decoded = unquote(unquote(value))
                filter_chars_found = [c for c in decoded if c in LDAP_FILTER_CHARS]
                if len(filter_chars_found) >= 2:
                    signals.append(f"filter_chars_in_{name}")
                if LDAP_FILTER_INJECTION_RE.search(decoded):
                    signals.append(f"filter_pattern_in_{name}")
    except Exception as exc:
        logger.warning("LDAP filter injection detection failed for %s: %s", url, exc)
    return signals


def _detect_ldap_auth_endpoint(url: str) -> bool:
    """Check if URL path matches LDAP authentication endpoint patterns."""
    try:
        from urllib.parse import urlparse

        path = urlparse(url).path.lower()
        return any(hint in path for hint in LDAP_AUTH_PATH_HINTS)
    except Exception:
        return False


def _scan_response_for_ldap_errors(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Scan response body for LDAP error message patterns."""
    matches: list[dict[str, Any]] = []
    body = response.get("body_text") or response.get("body") or ""
    if not body:
        return matches
    body_preview = body[:20000]
    for pattern in LDAP_ERROR_PATTERNS:
        match = pattern.search(body_preview)
        if match:
            matches.append(
                {
                    "pattern": pattern.pattern,
                    "matched_text": match.group(0)[:200],
                    "position": match.start(),
                }
            )
    return matches


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


def ldap_injection_surface_analyzer(
    urls: set[str] | None = None,
    responses: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Analyze URLs and responses for LDAP injection surface indicators.

    Performs three-phase analysis:
    1. URL parameter analysis for LDAP-related query parameters
    2. Response body analysis for LDAP error messages
    3. Combined analysis for LDAP auth endpoints with injection-susceptible params

    Args:
        urls: Set of URLs to analyze for LDAP-related parameters.
        responses: List of HTTP response dicts to scan for LDAP errors.

    Returns:
        List of finding dictionaries with severity, confidence, and evidence.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    url_set = urls or set()
    resp_list = responses or []

    url_findings: dict[str, dict[str, Any]] = {}

    for url in sorted(url_set):
        if not url or not url.startswith(("http://", "https://")):
            continue

        signals: list[str] = []
        evidence: dict[str, Any] = {}
        severity = "info"
        title_parts: list[str] = []

        ldap_params = _detect_ldap_params_in_url(url)
        filter_signals = _detect_ldap_filter_injection_in_url(url)
        is_auth_endpoint = _detect_ldap_auth_endpoint(url)

        if ldap_params:
            signals.extend(f"ldap_param:{p}" for p in ldap_params)
            evidence["ldap_parameters"] = ldap_params
            title_parts.append(f"LDAP parameters detected ({', '.join(ldap_params[:5])})")

        if filter_signals:
            signals.extend(filter_signals)
            evidence["filter_injection_indicators"] = filter_signals
            title_parts.append("LDAP filter injection characters in parameters")

        if is_auth_endpoint:
            signals.append("ldap_auth_endpoint")
            evidence["auth_endpoint"] = True
            title_parts.append("LDAP authentication endpoint")

        if not signals:
            continue

        if is_auth_endpoint and (ldap_params or filter_signals):
            severity = "high"
            if filter_signals:
                severity = "high"
                title_parts.insert(0, "LDAP auth endpoint with filter injection surface")
            else:
                title_parts.insert(0, "LDAP auth endpoint with LDAP parameters")
        elif filter_signals:
            severity = "medium"
            title_parts.insert(0, "LDAP filter injection patterns in URL parameters")
        elif is_auth_endpoint:
            severity = "medium"
        else:
            severity = "low"

        title = " | ".join(title_parts) if title_parts else "LDAP surface indicator"
        explanation = (
            f"URL contains LDAP-related indicators: {', '.join(signals[:8])}. "
            f"Endpoint type: {classify_endpoint(url)}. "
            f"{'This is an authentication endpoint which increases risk.' if is_auth_endpoint else ''} "
            f"{'Filter injection characters detected in parameter values.' if filter_signals else ''}"
        ).strip()

        confidence = normalized_confidence(
            base=0.45 if severity == "low" else 0.60 if severity == "medium" else 0.75,
            score=8 if severity == "high" else 5 if severity == "medium" else 2,
            signals=signals,
        )

        dedup_key = f"{endpoint_signature(url)}|{severity}|{','.join(sorted(signals)[:3])}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        status_code = None
        finding = _build_finding(
            url=url,
            status_code=status_code,
            category="ldap_injection_surface",
            title=title,
            severity=severity,
            confidence=confidence,
            signals=signals,
            evidence=evidence,
            explanation=explanation,
        )
        url_findings[endpoint_base_key(url)] = finding

    for finding in url_findings.values():
        findings.append(finding)

    response_by_url: dict[str, dict[str, Any]] = {}
    for resp in resp_list:
        resp_url = str(resp.get("url", "")).strip()
        if resp_url:
            response_by_url[resp_url] = resp

    seen_errors: set[str] = set()
    for resp in resp_list:
        resp_url = str(resp.get("url", "")).strip()
        if not resp_url:
            continue

        status_code = resp.get("status_code")
        ldap_errors = _scan_response_for_ldap_errors(resp)
        if not ldap_errors:
            continue

        signals = [f"ldap_error:{e['pattern'][:40]}" for e in ldap_errors[:6]]
        evidence = {
            "ldap_errors": [
                {"pattern": e["pattern"], "matched_text": e["matched_text"]}
                for e in ldap_errors[:10]
            ],
        }

        error_types = [e["matched_text"].lower() for e in ldap_errors]
        has_auth_error = any(
            t in " ".join(error_types) for t in ("invalidcredentials", "authentication", "bind")
        )
        has_schema_error = any(
            t in " ".join(error_types) for t in ("constraint", "violat", "invalid dn", "unwilling")
        )

        if has_auth_error:
            severity = "high"
        elif has_schema_error:
            severity = "medium"
        else:
            severity = "medium"

        title = f"LDAP error messages in response ({len(ldap_errors)} patterns)"
        confidence = normalized_confidence(
            base=0.65 if severity == "high" else 0.55,
            score=8 if severity == "high" else 5,
            signals=signals,
        )

        explanation = (
            f"Response body contains {len(ldap_errors)} LDAP error pattern(s). "
            f"Status code: {status_code}. "
            f"Matched patterns: {', '.join(e['matched_text'][:80] for e in ldap_errors[:5])}. "
            f"This suggests the backend uses LDAP for directory operations and may expose error details."
        )

        dedup_key = f"{resp_url}|ldap_error|{','.join(sorted(set(e['pattern'][:30] for e in ldap_errors[:3])))}"
        if dedup_key in seen_errors:
            continue
        seen_errors.add(dedup_key)

        findings.append(
            _build_finding(
                url=resp_url,
                status_code=status_code,
                category="ldap_injection_surface",
                title=title,
                severity=severity,
                confidence=confidence,
                signals=signals,
                evidence=evidence,
                explanation=explanation,
            )
        )

    for url in sorted(url_set):
        if not url or not url.startswith(("http://", "https://")):
            continue
        current_resp: dict[str, Any] | None = response_by_url.get(url)
        if not current_resp:
            continue
        resp_body = current_resp.get("body_text") or current_resp.get("body") or ""
        if not resp_body:
            continue
        ldap_params = _detect_ldap_params_in_url(url)
        if not ldap_params:
            continue
        body_lower = resp_body[:10000].lower()
        ldap_context_in_body = any(
            token in body_lower
            for token in (
                "ldap",
                "directory",
                "active directory",
                "authentication",
                "bind",
                "search",
                "cn=",
                "dn=",
                "uid=",
                "objectclass",
            )
        )
        if ldap_context_in_body:
            signals = [f"ldap_param_in_url_and_body:{p}" for p in ldap_params[:5]]
            signals.append("ldap_context_in_response_body")
            evidence = {
                "ldap_parameters": ldap_params,
                "body_context_indicators": True,
            }
            severity = "high"
            title = "LDAP parameters in URL with LDAP context in response body"
            confidence = normalized_confidence(
                base=0.70,
                score=8,
                signals=signals,
            )
            explanation = (
                f"URL contains LDAP parameters ({', '.join(ldap_params[:5])}) "
                f"and the response body contains LDAP-related context. "
                f"This strongly suggests active LDAP backend integration."
            )
            dedup_key = f"{endpoint_signature(url)}|ldap_context_body"
            if dedup_key not in seen:
                seen.add(dedup_key)
                findings.append(
                    _build_finding(
                        url=url,
                        status_code=resp.get("status_code"),
                        category="ldap_injection_surface",
                        title=title,
                        severity=severity,
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

    return findings[:100]

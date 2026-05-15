"""HTTP Parameter Pollution active probe."""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis._core.http_request import _safe_request
from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity

HPP_DUPLICATE_PAYLOADS = [
    ("duplicate_id", "id=1&id=2"),
    ("duplicate_role", "role=user&role=admin"),
    ("duplicate_action", "action=view&action=delete"),
    ("duplicate_user", "user=alice&user=bob"),
    ("duplicate_order", "order=asc&order=desc"),
    ("duplicate_sort", "sort=name&sort=id"),
    ("duplicate_limit", "limit=10&limit=100"),
    ("duplicate_page", "page=1&page=2"),
    ("duplicate_token", "token=abc&token=xyz"),
    ("duplicate_redirect", "redirect=/home&redirect=/admin"),
]

HPP_ENCODING_PAYLOADS = [
    ("encoded_equals", "id=1&id%3d2"),
    ("encoded_ampersand", "id=1%26id=2"),
    ("encoded_param_name", "id=1&i%64=2"),
    ("double_encoded", "id%253d1&id=2"),
    ("unicode_encoded", "id=1&\u0069d=2"),
]

HPP_FORMAT_PAYLOADS = [
    ("comma_separated", "id=1,2"),
    ("semicolon_separated", "id=1;id=2"),
    ("pipe_separated", "id=1|id=2"),
    ("space_separated", "id=1+2"),
    ("array_style", "id[]=1&id[]=2"),
    ("json_array", "id=[1,2]"),
]

HPP_WAF_BYPASS_PAYLOADS = [
    ("waf_split_1", "param1=val&param1=ue"),
    ("waf_split_2", "param=evil&param=;id"),
    ("waf_case", "PARAM=val&param=evil"),
    ("waf_space", "param =val&param=evil"),
]

HPP_ERROR_RE = re.compile(
    r"(?i)(?:parameter.*pollution|duplicate.*param|multiple.*value|"
    r"ambiguous.*param|conflicting.*param|invalid.*parameter|"
    r"param.*error|unexpected.*param|too.*many.*param|"
    r"array.*expected|string.*expected|type.*mismatch)"
)


def _build_duplicate_url(parsed: Any, param_name: str, val1: str, val2: str) -> str:
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = []
    replaced = False
    for k, v in query_pairs:
        new_pairs.append((k, v))
        if k == param_name and not replaced:
            new_pairs.append((k, val2))
            replaced = True
    if not replaced:
        new_pairs.append((param_name, val1))
        new_pairs.append((param_name, val2))
    return normalize_url(urlunparse(parsed._replace(query=urlencode(new_pairs, doseq=True))))


def _build_encoded_url(parsed: Any, param_name: str, val1: str, val2: str) -> str:
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = []
    replaced = False
    for k, v in query_pairs:
        new_pairs.append((k, v))
        if k == param_name and not replaced:
            new_pairs.append((param_name + "%3d", val2))
            replaced = True
    if not replaced:
        new_pairs.append((param_name, val1))
        new_pairs.append((param_name + "%3d", val2))
    return normalize_url(
        urlunparse(parsed._replace(query="&".join(f"{k}={v}" for k, v in new_pairs)))
    )


def _build_array_url(parsed: Any, param_name: str, val1: str, val2: str) -> str:
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = []
    replaced = False
    for k, v in query_pairs:
        if k == param_name and not replaced:
            new_pairs.append((f"{param_name}[]", val1))
            new_pairs.append((f"{param_name}[]", val2))
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append((f"{param_name}[]", val1))
        new_pairs.append((f"{param_name}[]", val2))
    return normalize_url(urlunparse(parsed._replace(query=urlencode(new_pairs, doseq=True))))


def hpp_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test endpoints for HTTP Parameter Pollution vulnerabilities.

    Sends duplicate parameters, encoded parameters, and different formatting
    styles to detect parameter parsing inconsistencies and WAF bypasses.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of HPP findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        original_resp = response_cache.get(url)
        if not original_resp:
            original_resp = _safe_request(url, timeout=8)
        if not original_resp or original_resp.get("status") in (404, 410, 503):
            continue

        original_status = original_resp.get("status", 0)
        original_body = str(original_resp.get("body") or original_resp.get("body_text") or "")
        original_length = len(original_body)

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        param_names_seen: set[str] = set()
        for param_name, param_value in query_pairs:
            if param_name in param_names_seen:
                continue
            param_names_seen.add(param_name)

            if len(url_probes) >= 4:
                break

            dup_url = _build_duplicate_url(parsed, param_name, param_value, "polluted")
            response = response_cache.request(
                dup_url,
                headers={"Cache-Control": "no-cache", "X-HPP-Probe": "1"},
            )
            if not response:
                response = _safe_request(dup_url, timeout=10)
            if not response:
                continue

            body = str(response.get("body_text") or response.get("body") or "")[:8000]
            status = int(response.get("status_code") or response.get("status") or 0)
            body_length = len(body)

            issues_for_hit: list[str] = []

            if HPP_ERROR_RE.search(body):
                issues_for_hit.append("hpp_error_pattern")
            elif status != original_status and status not in (404, 400):
                issues_for_hit.append("hpp_status_code_change")
            elif original_length > 0 and body_length > 0:
                length_diff = abs(body_length - original_length)
                length_pct = (length_diff / original_length * 100) if original_length > 0 else 0
                if length_pct > 30:
                    issues_for_hit.append("hpp_body_length_change")
                elif body != original_body[:8000] and "polluted" in body.lower():
                    issues_for_hit.append("hpp_parameter_reflection")

            if not issues_for_hit:
                enc_url = _build_encoded_url(parsed, param_name, param_value, "polluted")
                enc_response = response_cache.request(
                    enc_url,
                    headers={"Cache-Control": "no-cache", "X-HPP-Probe": "1"},
                )
                if not enc_response:
                    enc_response = _safe_request(enc_url, timeout=10)
                if enc_response:
                    enc_body = str(enc_response.get("body_text") or enc_response.get("body") or "")[
                        :8000
                    ]
                    enc_status = int(
                        enc_response.get("status_code") or enc_response.get("status") or 0
                    )
                    if enc_status != status:
                        issues_for_hit.append("hpp_encoding_behavior_diff")
                    elif enc_body != body and len(enc_body) > 0:
                        issues_for_hit.append("hpp_encoding_response_diff")

            if not issues_for_hit:
                arr_url = _build_array_url(parsed, param_name, param_value, "polluted")
                arr_response = response_cache.request(
                    arr_url,
                    headers={"Cache-Control": "no-cache", "X-HPP-Probe": "1"},
                )
                if not arr_response:
                    arr_response = _safe_request(arr_url, timeout=10)
                if arr_response:
                    arr_body = str(arr_response.get("body_text") or arr_response.get("body") or "")[
                        :8000
                    ]
                    arr_status = int(
                        arr_response.get("status_code") or arr_response.get("status") or 0
                    )
                    if arr_status != status and arr_status not in (400, 404):
                        issues_for_hit.append("hpp_array_vs_duplicate_diff")
                    elif arr_body != body and len(arr_body) > 0:
                        issues_for_hit.append("hpp_format_parsing_diff")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "parameter": param_name,
                        "original_value": param_value,
                        "payload_type": "duplicate_parameter",
                        "status_code": status,
                        "issues": issues_for_hit,
                    }
                )

        for bypass_name, bypass_query in HPP_WAF_BYPASS_PAYLOADS:
            if len(url_probes) >= 4:
                break
            test_pairs = list(query_pairs)
            parts = bypass_query.split("=", 1)
            test_pairs.append((parts[0], parts[1] if len(parts) > 1 else ""))
            test_url = normalize_url(
                urlunparse(parsed._replace(query=urlencode(test_pairs, doseq=True)))
            )

            response = _safe_request(test_url, timeout=10)
            if not response:
                continue

            body = str(response.get("body") or "")[:8000]
            status = response.get("status", 0)

            bypass_issues: list[str] = []
            if status != original_status and status not in (404, 400):
                bypass_issues.append("hpp_waf_bypass_status")
            elif HPP_ERROR_RE.search(body):
                bypass_issues.append("hpp_waf_bypass_error")
            elif status == 200 and original_status in (403, 401):
                bypass_issues.append("hpp_waf_bypass_auth")

            if bypass_issues:
                url_issues.extend(bypass_issues)
                url_probes.append(
                    {
                        "parameter": "multiple",
                        "payload_type": bypass_name,
                        "status_code": status,
                        "issues": bypass_issues,
                    }
                )

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]

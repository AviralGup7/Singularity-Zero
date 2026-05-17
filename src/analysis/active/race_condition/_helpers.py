"""Helper functions for race condition probing."""

import hashlib
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from ._constants import (
    AUTH_RACE_PATH_KEYWORDS,
    RACE_PRONE_PATH_KEYWORDS,
    RC_CONFIDENCE,
    RC_SEVERITY,
    RESOURCE_ALLOCATION_KEYWORDS,
    STATE_TRANSITION_KEYWORDS,
)

logger = logging.getLogger(__name__)


def compute_body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def extract_json_value(body: str, *keys: str) -> str | int | float | None:
    try:
        data = json.loads(body)
    except json.JSONDecodeError, ValueError:
        return None
    current: Any = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    if isinstance(current, (str, int, float)):
        return current
    return None


def detect_balance_changes(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    balances: list[float] = []
    for resp in responses:
        body = str(resp.get("body_text", "") or "")
        if not body:
            continue
        val = extract_json_value(body, "balance")
        if val is None:
            val = extract_json_value(body, "new_balance")
        if val is None:
            val = extract_json_value(body, "remaining")
        if val is None:
            val = extract_json_value(body, "amount")
        if val is not None:
            try:
                balances.append(float(val))
            except (TypeError, ValueError) as exc:
                logger.debug("Ignored: %s", exc)
    if len(balances) < 2:
        return []
    unique_balances = sorted(set(balances))
    if len(unique_balances) > 1:
        return [
            {
                "type": "balance_inconsistency",
                "unique_values": unique_balances[:10],
                "value_count": len(unique_balances),
                "all_values": balances[:20],
            }
        ]
    return []


def detect_duplicate_processing(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    duplicates: list[dict[str, Any]] = []
    seen_ids: dict[str, int] = {}
    success_count = 0
    for resp in responses:
        body = str(resp.get("body_text", "") or "")
        if not body:
            continue
        status = int(resp.get("status_code") or 0)
        if 200 <= status < 300:
            success_count += 1
        op_id = extract_json_value(body, "id")
        if op_id is None:
            op_id = extract_json_value(body, "transaction_id")
        if op_id is None:
            op_id = extract_json_value(body, "order_id")
        if op_id is None:
            op_id = extract_json_value(body, "claim_id")
        if op_id is not None:
            id_str = str(op_id)
            if id_str in seen_ids:
                duplicates.append(
                    {"type": "duplicate_id", "id": id_str, "occurrences": seen_ids[id_str] + 1}
                )
            seen_ids[id_str] = seen_ids.get(id_str, 0) + 1
    if duplicates:
        return duplicates
    if success_count > 1:
        return [{"type": "multiple_success", "success_count": success_count}]
    return []


def detect_toctou(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    status_codes = [int(r.get("status_code") or 0) for r in responses]
    success_codes = {200, 201, 202, 204}
    error_codes = {400, 403, 404, 409, 422, 500}
    successes = sum(1 for c in status_codes if c in success_codes)
    conflicts = sum(1 for c in status_codes if c == 409)
    client_errors = sum(1 for c in status_codes if c in error_codes)
    findings: list[dict[str, Any]] = []
    if successes > 0 and conflicts > 0:
        findings.append(
            {
                "type": "toctou_check_then_fail",
                "success_count": successes,
                "conflict_count": conflicts,
                "description": "Some requests succeeded while others received 409 Conflict",
            }
        )
    if successes > 0 and client_errors > successes:
        findings.append(
            {
                "type": "toctou_inconsistent_validation",
                "success_count": successes,
                "error_count": client_errors,
                "description": "Mixed success and client error responses indicate TOCTOU",
            }
        )
    return findings


def detect_response_inconsistency(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    body_hashes: dict[str, int] = {}
    status_counts: dict[int, int] = {}
    for resp in responses:
        body = str(resp.get("body_text", "") or "")
        h = compute_body_hash(body)
        body_hashes[h] = body_hashes.get(h, 0) + 1
        status = int(resp.get("status_code") or 0)
        status_counts[status] = status_counts.get(status, 0) + 1
    findings: list[dict[str, Any]] = []
    unique_bodies = len(body_hashes)
    if unique_bodies > 1:
        findings.append(
            {
                "type": "response_body_variation",
                "unique_body_count": unique_bodies,
                "total_responses": len(responses),
                "body_hash_distribution": {
                    h: c for h, c in sorted(body_hashes.items(), key=lambda x: -x[1])[:5]
                },
            }
        )
    unique_statuses = len(status_counts)
    if unique_statuses > 1:
        findings.append(
            {"type": "status_code_variation", "status_codes": dict(sorted(status_counts.items()))}
        )
    return findings


def detect_timing_discrepancy(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latencies: list[float] = []
    for resp in responses:
        latency = resp.get("latency_seconds")
        if latency is not None:
            try:
                latencies.append(float(latency))
            except (TypeError, ValueError) as exc:
                logger.debug("Ignored: %s", exc)
    if len(latencies) < 2:
        return []
    min_lat = min(latencies)
    max_lat = max(latencies)
    avg_lat = sum(latencies) / len(latencies)
    if max_lat > 0 and (max_lat - min_lat) / max_lat > 0.5:
        return [
            {
                "type": "timing_discrepancy",
                "min_latency": round(min_lat, 4),
                "max_latency": round(max_lat, 4),
                "avg_latency": round(avg_lat, 4),
                "variance_ratio": round((max_lat - min_lat) / max_lat, 4),
            }
        ]
    return []


def is_race_prone_endpoint(url: str) -> tuple[bool, str]:
    lowered = url.lower()
    for keyword in RACE_PRONE_PATH_KEYWORDS:
        if keyword in lowered:
            return True, "state_change"
    for keyword in AUTH_RACE_PATH_KEYWORDS:
        if keyword in lowered:
            return True, "auth_flow"
    for keyword in STATE_TRANSITION_KEYWORDS:
        if keyword in lowered:
            return True, "state_transition"
    for keyword in RESOURCE_ALLOCATION_KEYWORDS:
        if keyword in lowered:
            return True, "resource_allocation"
    return False, ""


def classify_race_type(url: str) -> str:
    lowered = url.lower()
    financial = {
        "payment",
        "pay",
        "charge",
        "bill",
        "transfer",
        "withdraw",
        "deposit",
        "balance",
        "wallet",
        "credit",
        "debit",
        "checkout",
        "purchase",
    }
    coupon = {"coupon", "discount", "promo", "voucher", "redeem"}
    auth = {
        "register",
        "signup",
        "login",
        "signin",
        "authenticate",
        "token",
        "verify",
        "confirm",
        "reset",
        "activate",
    }
    vote_claim = {"vote", "claim", "apply"}
    resource = {
        "book",
        "booking",
        "reserve",
        "reservation",
        "seat",
        "ticket",
        "stock",
        "inventory",
        "quantity",
        "allocate",
        "assign",
    }
    state = {
        "status",
        "state",
        "approve",
        "reject",
        "cancel",
        "enable",
        "disable",
        "lock",
        "unlock",
        "publish",
    }
    for kw in financial:
        if kw in lowered:
            return "financial"
    for kw in coupon:
        if kw in lowered:
            return "coupon_discount"
    for kw in auth:
        if kw in lowered:
            return "auth_flow"
    for kw in vote_claim:
        if kw in lowered:
            return "vote_claim"
    for kw in resource:
        if kw in lowered:
            return "resource_allocation"
    for kw in state:
        if kw in lowered:
            return "state_transition"
    return "general"


def calculate_confidence(issues: list[str]) -> float:
    if not issues:
        return 0.5
    max_conf = max(RC_CONFIDENCE.get(issue, 0.5) for issue in issues)
    bonus = min(0.08, len(issues) * 0.02)
    return round(min(0.95, max_conf + bonus), 2)


def calculate_severity(issues: list[str]) -> str:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    if not issues:
        return "low"
    return min(
        (RC_SEVERITY.get(issue, "low") for issue in issues), key=lambda s: severity_order.get(s, 3)
    )


def make_concurrent_requests(
    response_cache: ResponseCache,
    url: str,
    count: int,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    request_headers = dict(headers or {})
    request_headers["Cache-Control"] = "no-cache"
    request_headers["X-Race-Condition-Probe"] = "1"

    def _single_request(index: int) -> dict[str, Any]:
        start = time.monotonic()
        resp = response_cache.request(url, method=method, headers=request_headers, body=body)
        latency = time.monotonic() - start
        if resp is not None:
            resp = dict(resp)
            resp["latency_seconds"] = latency
            resp["_request_index"] = index
        return resp or {}

    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = {executor.submit(_single_request, i): i for i in range(count)}
        for future in as_completed(futures):
            try:
                result = future.result(timeout=30)
                if result:
                    results.append(result)
            except Exception as e:
                logging.debug("Race probe request failed: %s", e)
    results.sort(key=lambda r: r.get("_request_index", 0))
    return results


def build_finding(
    url: str,
    race_type: str,
    issues: list[str],
    evidence: list[dict[str, Any]],
    confidence: float,
    severity: str,
) -> dict[str, Any]:
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "category": "race_condition",
        "title": f"Race condition vulnerability detected: {url}",
        "race_type": race_type,
        "severity": severity,
        "confidence": round(confidence, 2),
        "score": 100
        if severity == "critical"
        else 80
        if severity == "high"
        else 50
        if severity == "medium"
        else 20,
        "signals": sorted(set(issues)),
        "evidence": {"issues": issues, "evidence": evidence},
        "explanation": f"Endpoint '{url}' exhibits race condition vulnerabilities with {len(issues)} distinct issue types detected. Race type: {race_type}.",
    }

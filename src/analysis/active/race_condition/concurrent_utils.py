"""Utility functions for concurrent race-condition requests and response analysis."""

import asyncio
import dataclasses
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

try:
    import httpx
except Exception:  # pragma: no cover - optional dependency guard
    logging.getLogger(__name__).warning("Failed to import httpx", exc_info=True)
    httpx = None  # type: ignore[assignment]

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

from ._constants import (
    AUTH_RACE_PATH_KEYWORDS,
    RACE_PRONE_PATH_KEYWORDS,
    RC_CONFIDENCE,
    RC_SEVERITY,
    RESOURCE_ALLOCATION_KEYWORDS,
    STATE_TRANSITION_KEYWORDS,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model for race-probe responses
# ---------------------------------------------------------------------------
@dataclass
class RaceResponse:
    request_index: int
    url: str
    status_code: int | None
    body_text: str | None
    headers: dict[str, str] = dataclasses.field(default_factory=dict)
    latency_seconds: float = 0.0
    sent_at_ns: int = 0
    received_at_ns: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_index": self.request_index,
            "url": self.url,
            "status_code": self.status_code,
            "body_text": self.body_text,
            "body_length": (len(self.body_text) if self.body_text is not None else 0),
            "headers": dict(self.headers),
            "latency_seconds": self.latency_seconds,
            "sent_at_ns": self.sent_at_ns,
            "received_at_ns": self.received_at_ns,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------
def compute_body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def extract_json_value(body: str, *keys: str) -> str | int | float | None:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
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


def detect_balance_changes(
    responses: list[dict[str, Any]] | list[RaceResponse],
) -> list[dict[str, Any]]:
    balances: list[float] = []
    for resp in responses:
        body = str(
            resp.get("body_text", "") or "" if isinstance(resp, dict) else (resp.body_text or "")
        )
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


def detect_duplicate_processing(
    responses: list[dict[str, Any]] | list[RaceResponse],
) -> list[dict[str, Any]]:
    duplicates: list[dict[str, Any]] = []
    seen_ids: dict[str, int] = {}
    success_count = 0
    for resp in responses:
        body = str(
            resp.get("body_text", "") or "" if isinstance(resp, dict) else (resp.body_text or "")
        )
        if not body:
            continue
        status = int(
            resp.get("status_code") or 0 if isinstance(resp, dict) else (resp.status_code or 0)
        )
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


def detect_toctou(
    responses: list[dict[str, Any]] | list[RaceResponse],
) -> list[dict[str, Any]]:
    status_codes = [
        int(r.get("status_code") or 0 if isinstance(r, dict) else (r.status_code or 0))
        for r in responses
    ]
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


def detect_response_inconsistency(
    responses: list[dict[str, Any]] | list[RaceResponse],
) -> list[dict[str, Any]]:
    body_hashes: dict[str, int] = {}
    status_counts: dict[int, int] = {}
    for resp in responses:
        body = str(
            resp.get("body_text", "") or "" if isinstance(resp, dict) else (resp.body_text or "")
        )
        h = compute_body_hash(body)
        body_hashes[h] = body_hashes.get(h, 0) + 1
        status = int(
            resp.get("status_code") or 0 if isinstance(resp, dict) else (resp.status_code or 0)
        )
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
            {
                "type": "status_code_variation",
                "status_codes": dict(sorted(status_counts.items())),
            }
        )
    return findings


def detect_timing_discrepancy(
    responses: list[dict[str, Any]] | list[RaceResponse],
) -> list[dict[str, Any]]:
    latencies: list[float] = []
    for resp in responses:
        latency = resp.get("latency_seconds") if isinstance(resp, dict) else resp.latency_seconds
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
    financial = {"payment", "pay", "charge", "bill", "transfer", "withdraw", "deposit"}
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
    resource = {"book", "booking", "reserve", "reservation", "seat", "ticket", "stock", "inventory"}
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
    }
    for kw in list(financial) + ["balance", "wallet", "credit", "debit", "checkout", "purchase"]:
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
        (RC_SEVERITY.get(issue, "low") for issue in issues),
        key=lambda s: severity_order.get(s, 3),
    )


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
        "explanation": (
            f"Endpoint '{url}' exhibits race condition vulnerabilities with "
            f"{len(issues)} distinct issue types detected. Race type: {race_type}."
        ),
    }


# ---------------------------------------------------------------------------
# asyncio single-host race with true simultaneous request firing
# ---------------------------------------------------------------------------
async def _race_single_request_async(
    client: "httpx.AsyncClient",
    url: str,
    index: int,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
) -> RaceResponse:
    sent_at_ns = time.perf_counter_ns()
    status_code: int | None = None
    body_text: str | None = None
    response_headers: dict[str, str] = {}
    error: str | None = None
    try:
        resp = await client.request(
            method.upper(),
            url,
            headers=headers,
            content=body,
        )
        received_at_ns = time.perf_counter_ns()
        status_code = resp.status_code
        body_text = resp.text
        response_headers = dict(resp.headers)
        latency_seconds = (received_at_ns - sent_at_ns) / 1e9
    except Exception as exc:  # noqa: BLE001
        received_at_ns = time.perf_counter_ns()
        error = str(exc)
        latency_seconds = (received_at_ns - sent_at_ns) / 1e9
        logger.debug("Race probe request %d failed: %s", index, error)
    return RaceResponse(
        request_index=index,
        url=url,
        status_code=status_code,
        body_text=body_text,
        headers=response_headers,
        latency_seconds=latency_seconds,
        sent_at_ns=sent_at_ns,
        received_at_ns=received_at_ns,
        error=error,
    )


async def _race_cache_request_async(
    response_cache: Any,
    url: str,
    index: int,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
) -> RaceResponse:

    sent_at_ns = time.perf_counter_ns()
    status_code: int | None = None
    body_text: str | None = None
    response_headers: dict[str, str] = {}
    error: str | None = None
    try:
        record = await asyncio.to_thread(
            response_cache.request,
            url,
            method=method,
            headers=headers,
            body=body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body,
        )
        received_at_ns = time.perf_counter_ns()
        if record is not None:
            status_code = record.get("status_code") or None
            body_text = record.get("body_text") or None
            response_headers = record.get("headers") or {}
        latency_seconds = (received_at_ns - sent_at_ns) / 1e9
    except Exception as exc:  # noqa: BLE001
        received_at_ns = time.perf_counter_ns()
        error = str(exc)
        latency_seconds = (received_at_ns - sent_at_ns) / 1e9
        logger.debug("Race cache request %d failed: %s", index, error)
    return RaceResponse(
        request_index=index,
        url=url,
        status_code=status_code,
        body_text=body_text,
        headers=response_headers,
        latency_seconds=latency_seconds,
        sent_at_ns=sent_at_ns,
        received_at_ns=received_at_ns,
        error=error,
    )


async def _execute_race(
    response_cache: Any | None,
    url: str,
    count: int,
    method: str,
    headers: dict[str, str] | None,
    body: bytes | None,
) -> list[RaceResponse]:
    request_headers = dict(headers or {})
    request_headers["Cache-Control"] = "no-cache"
    request_headers["X-Race-Condition-Probe"] = "1"

    if httpx is None:
        raise ImportError("httpx is required for make_concurrent_requests. Install httpx==0.28.0.")

    if response_cache is None:
        _RACE_MAX_CONNECTIONS = 100
        _RACE_MAX_KEEPALIVE = 20
        limits = httpx.Limits(
            max_connections=_RACE_MAX_CONNECTIONS,
            max_keepalive_connections=_RACE_MAX_KEEPALIVE,
        )
        from src.core.utils.shared_sessions import _i29_async_request_hook

        async with httpx.AsyncClient(
            limits=limits,
            timeout=30.0,
            event_hooks={"request": [_i29_async_request_hook]},
        ) as client:
            bound_tasks = [
                _race_single_request_async(client, url, i, method, request_headers, body)
                for i in range(count)
            ]
            responses = list(await asyncio.gather(*bound_tasks, return_exceptions=False))
    else:
        bound_tasks = [
            _race_cache_request_async(response_cache, url, i, method, request_headers, body)
            for i in range(count)
        ]
        responses = list(await asyncio.gather(*bound_tasks, return_exceptions=False))

    responses.sort(key=lambda r: r.request_index)
    return responses


def make_concurrent_requests(
    response_cache: Any | None,
    url: str,
    count: int,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
) -> list[dict[str, Any]]:
    request_body = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None and loop.is_running():
        coro = _execute_race(response_cache, url, count, method, headers, request_body)
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        race_responses: list[RaceResponse] = future.result(timeout=60)
    else:
        race_responses = asyncio.run(
            _execute_race(response_cache, url, count, method, headers, request_body)
        )
    return [r.to_dict() for r in race_responses]

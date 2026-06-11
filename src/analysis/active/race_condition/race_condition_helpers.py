"""Helper functions for race condition probing.

Part A updates:
- Replaced ThreadPoolExecutor-based concurrency with asyncio + httpx.AsyncClient so that
  race requests fire near-simultaneously on a single host. Uses
  ``asyncio.gather()`` for true concurrent scheduling and ``time.perf_counter_ns()`` to
  record per-request inter-arrival jitter.
- ``make_concurrent_requests`` still accepts a ``ResponseCache`` instance, but also works
  in a pure asyncio mode that does not require a cache.
- Added ``RaceCoordinator`` for distributed (multi-worker) race coordination and UDP
  timestamp sync helpers.
- Added ``measure_from_response_date_header`` for server-side timing baseline.

Part B updates:
- Added ``ActorRaceTester`` with multi-actor race, state comparison, and double-submit
  primitives.
"""

import asyncio
import dataclasses
import hashlib
import json
import logging
import math
import socket
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

try:
    import httpx
except Exception:  # pragma: no cover - optional dependency guard
    httpx = None  # type: ignore[assignment]

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
# Existing utility helpers (unchanged)
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
# Part A: asyncio single-host race with true simultaneous request firing
# ---------------------------------------------------------------------------
# ``make_concurrent_requests`` now provides two paths:
#
# 1. **Pure asyncio path (default, `response_cache=None`)** — uses
#    ``httpx.AsyncClient(limits=httpx.Limits(max_connections=0))`` to disable
#    client-side serialization (the pool cap is 0 = unlimited concurrent
#    transports). Requests are fired via ``asyncio.gather`` so the event loop
#    schedules them in a single scheduler tick, achieving sub-millisecond
#    dispersion. Inter-arrival jitter is recorded with ``time.perf_counter_ns``.
#
# 2. **ResponseCache path** — falls back to ``asyncio.gather`` issuing requests
#    through ``response_cache._request_with_policy`` concurrently, bypassing the
#    prior ThreadPoolExecutor serialization on Windows that masked sub-5ms races.
#
# The function is awaitable; if no event loop is running it creates a new one via
# ``asyncio.run`` so callers may continue using it synchronously:
#
#     responses = make_concurrent_requests(None, url, count=10)
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
    response_cache: ResponseCache,
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
    response_cache: ResponseCache | None,
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
        limits = httpx.Limits(max_connections=0, max_keepalive_connections=0)
        async with httpx.AsyncClient(limits=limits, timeout=30.0) as client:
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
    response_cache: ResponseCache | None,
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


# ---------------------------------------------------------------------------
# Part A continued: RaceCoordinator and distributed worker coordination
# ---------------------------------------------------------------------------
class RaceCoordinator:
    """Coordinates race-condition probes across distributed worker endpoints.

    * Single-host mode (default): ``workers`` is ``None`` or ``[]``. Uses the
      asyncio path from :func:`make_concurrent_requests`.
    * Distributed mode: ``workers`` points at lambda/cloud-function endpoints.
      ``distributed_race`` fans out to each worker which fires the requests
      simultaneously and returns ``(request_index, status_code, body_text)`` tuples.
    """

    def __init__(self, workers_config_path: str | None = None) -> None:
        self.workers: list[str] = []
        if workers_config_path:
            try:
                import json as _json

                with open(workers_config_path, encoding="utf-8") as fh:
                    data = _json.load(fh)
                if isinstance(data, list):
                    self.workers = [str(u) for u in data]
                elif isinstance(data, dict):
                    self.workers = [str(u) for u in data.get("workers", [])]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to load workers config: %s", exc)

    def distributed_race(
        self,
        workers: list[str],
        request_factory: Any,
        n: int = 10,
    ) -> list[dict[str, Any]]:
        """Fan-out race requests across *workers*.

        *request_factory* must be a callable ``(worker_url: str, index: int) -> Any``
        returning an awaitable or a completed response. For lambda-style endpoints
        the factory typically triggers a lambda invocation that fires the sub-race.
        """
        responses: list[dict[str, Any]] = []
        if not workers:
            return responses
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None and loop.is_running():
            coro = self._distributed_race_async(workers, request_factory, n)
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result(timeout=60)
        return asyncio.run(self._distributed_race_async(workers, request_factory, n))

    async def _distributed_race_async(
        self,
        workers: list[str],
        request_factory: Any,
        n: int,
    ) -> list[dict[str, Any]]:
        async with (
            httpx.AsyncClient(
                limits=httpx.Limits(max_connections=0, max_keepalive_connections=0),
                timeout=30.0,
            )
            if httpx is not None
            else _NullClient() as client
        ):
            tasks = []
            per_worker = max(1, math.ceil(n / max(len(workers), 1)))
            idx = 0
            for worker_url in workers:
                for i in range(per_worker):
                    if idx >= n:
                        break
                    tasks.append(self._fire_worker(client, worker_url, request_factory, idx))
                    idx += 1
            return list(await asyncio.gather(*tasks, return_exceptions=False))

    async def _fire_worker(
        self,
        client: Any,
        worker_url: str,
        request_factory: Any,
        index: int,
    ) -> dict[str, Any]:
        if request_factory is not None:
            spawned = request_factory(worker_url, index)
            if asyncio.iscoroutine(spawned):
                return cast(dict[str, Any], await spawned)
            if hasattr(spawned, "__await__"):
                return cast(dict[str, Any], await spawned.__await__())
            if spawned is not None:
                return dict(spawned)
            return {
                "request_index": index,
                "worker_url": worker_url,
                "error": "factory returned non-awaitable",
            }
        # Default: POST a race trigger to the worker
        if httpx is None or hasattr(client, "NOOP"):
            return {
                "request_index": index,
                "worker_url": worker_url,
                "status_code": None,
                "body_text": None,
                "headers": {},
                "latency_seconds": 0.0,
                "sent_at_ns": 0,
                "received_at_ns": 0,
                "error": "httpx not available",
            }
        sent_at_ns = time.perf_counter_ns()
        try:
            resp = await client.post(
                worker_url,
                json={"index": index, "action": "race"},
                headers={"X-Race-Condition-Probe": "1"},
            )
            received_at_ns = time.perf_counter_ns()
            return {
                "request_index": index,
                "worker_url": worker_url,
                "status_code": resp.status_code,
                "body_text": resp.text,
                "headers": dict(resp.headers),
                "latency_seconds": (received_at_ns - sent_at_ns) / 1e9,
                "sent_at_ns": sent_at_ns,
                "received_at_ns": received_at_ns,
            }
        except Exception as exc:  # noqa: BLE001
            received_at_ns = time.perf_counter_ns()
            return {
                "request_index": index,
                "worker_url": worker_url,
                "status_code": None,
                "body_text": None,
                "headers": {},
                "latency_seconds": (received_at_ns - sent_at_ns) / 1e9,
                "sent_at_ns": sent_at_ns,
                "received_at_ns": received_at_ns,
                "error": str(exc),
            }

    @staticmethod
    def measure_from_response_date_header(
        responses: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Use the ``Date`` HTTP response header delta as a server-side timing baseline.

        Returns summary statistics ``{"count", "min_delta_ms", "max_delta_ms",
        "avg_delta_ms", "jitter_ms"}`` where a high jitter implies the server received
        requests over a window wide enough to observe ordering races.
        """
        return _measure_date_header_jitter(responses)


def _measure_date_header_jitter(
    responses: list[dict[str, Any]],
) -> dict[str, Any]:
    if not responses:
        return {"count": 0}
    date_strs: list[str] = []
    for r in responses:
        headers = r.get("headers") or {}
        date_val = headers.get("Date") or headers.get("date")
        if date_val:
            date_strs.append(date_val)
    if len(date_strs) < 2:
        return {"count": len(date_strs), "insufficient_dates": True}
    parsed: list[datetime] = []
    for ds in date_strs:
        try:
            dt = datetime.strptime(ds, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=UTC)
            parsed.append(dt)
        except ValueError:
            continue
    if len(parsed) < 2:
        return {"count": len(parsed), "unparseable_dates": True}
    deltas = [(parsed[i + 1] - parsed[i]).total_seconds() * 1000 for i in range(len(parsed) - 1)]
    return {
        "count": len(parsed),
        "min_delta_ms": round(min(deltas), 4),
        "max_delta_ms": round(max(deltas), 4),
        "avg_delta_ms": round(sum(deltas) / len(deltas), 4),
        "jitter_ms": round(max(deltas) - min(deltas), 4) if deltas else 0.0,
    }


measure_from_response_date_header = _measure_date_header_jitter


class _NullClient:
    NOOP = True

    async def post(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("httpx is required for distributed race")

    async def aclose(self) -> None:
        return None

    async def __aenter__(self) -> "_NullClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None


# ---------------------------------------------------------------------------
# Part A continued: UDP timestamp sync helpers (similar to racey/TMNL NTP)
# ---------------------------------------------------------------------------
@dataclass
class _UdpTimestampResult:
    worker_url: str
    host: str
    port: int
    t1_ns: int
    t2_ns: int
    t3_ns: int
    t4_ns: int
    rtt_ns: int
    offset_ns: int


def _parse_udp_endpoint(worker_url: str) -> tuple[str, int]:
    if "://" in worker_url:
        worker_url = worker_url.split("://", 1)[1]
    if ":" in worker_url:
        host, _, port_s = worker_url.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError as exc:
            logger.warning("Operation failed in race_condition_helpers.py: %s", exc, exc_info=True)  # noqa: BLE001
    return worker_url, 0


def sync_workers(workers: list[str], timeout: float = 1.0) -> list[_UdpTimestampResult]:
    """Compute per-worker clock offset via a lightweight UDP timestamp exchange.

    For each worker, a small UDP packet containing ``t1`` is sent. The worker is
    expected to bounce the packet back immediately after stamping ``t2`` and ``t3``.
    Upon receipt ``t4`` is stamped. RTT and offset are computed as:

        offset = ((t2 - t1) + (t3 - t4)) / 2
        rtt    = (t4 - t1) - (t3 - t2)

    Workers running a compatible sync endpoint are required. Results with offsets
    exceeding 10 ms or RTT above 50 ms are filtered from the subsequent race
    scheduling step.
    """
    if not workers:
        return []
    results: list[_UdpTimestampResult] = []
    for worker_url in workers:
        host, port = _parse_udp_endpoint(worker_url)
        if not host or not port:
            logger.debug("Skipping sync for non-UDP worker URL: %s", worker_url)
            continue
        t1 = time.perf_counter_ns()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            payload = struct.pack("!Q", t1)
            sock.sendto(payload, (host, port))
            data, _ = sock.recvfrom(1024)
            t4 = time.perf_counter_ns()
            if len(data) >= 24:
                t1_echo, t2, t3 = struct.unpack("!QQQ", data[:24])
                t1 = t1_echo
                rtt = (t4 - t1) - (t3 - t2)
                offset = ((t2 - t1) + (t3 - t4)) / 2
                results.append(
                    _UdpTimestampResult(
                        worker_url=worker_url,
                        host=host,
                        port=port,
                        t1_ns=t1,
                        t2_ns=t2,
                        t3_ns=t3,
                        t4_ns=t4,
                        rtt_ns=rtt,
                        offset_ns=offset,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("UDP sync failed for %s: %s", worker_url, exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError as exc:
                    logger.warning(
                        "Operation failed in race_condition_helpers.py: %s", exc, exc_info=True
                    )  # noqa: BLE001
    return results


def select_synchronized_workers(
    sync_results: list[_UdpTimestampResult],
    max_offset_ns: int = 10_000_000,
    max_rtt_ns: int = 50_000_000,
) -> list[str]:
    """Filter workers whose clock offsets and RTT are within configured bounds."""
    return [
        r.worker_url
        for r in sync_results
        if abs(r.offset_ns) <= max_offset_ns and r.rtt_ns <= max_rtt_ns
    ]


# ---------------------------------------------------------------------------
# Part B: Multi-user actor race tester
# ---------------------------------------------------------------------------
class ActorRaceTester:
    """Race-condition tester using two independent authenticated actors.

    ``credential_vault`` must expose at least two credential sets with differing
    privilege levels.  Typical interfaces:

    * ``vault.credentials() -> list[dict[str, Any]]``
    * ``vault.get_credentials_for(resource_id: str, action: str) -> list[dict[str, Any]]``

    Each credential dict contains at minimum ``token`` / ``cookie`` and a
    ``privilege`` level such as ``"user"`` or ``"admin"``.
    """

    def __init__(self, credential_vault: Any) -> None:
        self.vault = credential_vault

    def _pick_two_credentials(
        self, resource_id: str, action: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        creds = self._resolve_credentials(resource_id, action)
        if len(creds) < 2:
            raise ValueError(
                "Credential vault must provide at least 2 credentials. "
                f"Got {len(creds)} credential(s)."
            )
        return creds[0], creds[1]

    def _resolve_credentials(self, resource_id: str, action: str) -> list[dict[str, Any]]:
        if hasattr(self.vault, "get_credentials_for"):
            creds = self.vault.get_credentials_for(resource_id, action)
            return list(creds or [])
        if hasattr(self.vault, "credentials"):
            return list(self.vault.credentials())
        return [self.vault] if isinstance(self.vault, dict) else []

    def _make_client(self, credential: dict[str, Any]) -> httpx.Client:
        headers: dict[str, str] = {}
        cookie_map: dict[str, str] = {}
        token = (
            credential.get("token")
            or credential.get("access_token")
            or credential.get("session_token")
            or ""
        )
        if token:
            auth_scheme = credential.get("auth_scheme", "Bearer")
            headers["Authorization"] = f"{auth_scheme} {token}"
        for key, value in credential.items():
            if "cookie" in key.lower():
                cookie_map[str(key)] = str(value)
        client = httpx.Client(
            headers=headers if headers else None,
            cookies=cookie_map if cookie_map else None,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=10.0, read=15.0, write=10.0, pool=5.0),
        )
        return client

    def race_action(
        self,
        actor_a_token: str,
        actor_b_token: str,
        resource_id: str,
        action: str,
        url_template: str,
        method: str = "POST",
        extra_headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Fire two concurrent requests from separate client instances.

        Each actor receives its own ``httpx.Client`` with a different cookie jar /
        Authorization header so that the server sees two independent authenticated
        sessions. Returns ``(actor_a_response, actor_b_response)`` dicts.
        """
        actor_a = {"token": actor_a_token, "auth_scheme": "Bearer"}
        actor_b = {"token": actor_b_token, "auth_scheme": "Bearer"}
        url = url_template.format(resource_id=resource_id, action=action)

        def _fire(credential: dict[str, Any]) -> dict[str, Any] | None:
            client = self._make_client(credential)
            try:
                req_body = body
                if (
                    req_body is not None
                    and isinstance(req_body, str)
                    and "Content-Type" not in (extra_headers or {})
                ):
                    req_headers = {"Content-Type": "application/json"}
                    req_headers.update(extra_headers or {})
                else:
                    req_headers = dict(extra_headers or {})
                with client:
                    resp = client.request(
                        method.upper(), url, headers=req_headers, content=req_body
                    )
                return {
                    "status_code": resp.status_code,
                    "body_text": resp.text,
                    "headers": dict(resp.headers),
                    "url": str(resp.url),
                }
            except Exception as exc:  # noqa: BLE001
                return {"status_code": None, "body_text": None, "headers": {}, "error": str(exc)}

        if httpx is None:
            raise ImportError("httpx is required for ActorRaceTester. Install httpx==0.28.0.")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _paired_race() -> tuple[dict[str, Any], dict[str, Any]]:
            coro_a = asyncio.to_thread(_fire, actor_a)
            coro_b = asyncio.to_thread(_fire, actor_b)
            results = await asyncio.gather(coro_a, coro_b)
            return (results[0] or {}, results[1] or {})

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_paired_race(), loop)
            return future.result(timeout=60)
        return asyncio.run(_paired_race())

    def compare_post_race_state(
        self,
        actor_a_state: dict[str, Any],
        actor_b_state: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Compare two post-race state dicts and return a list of ``Finding`` dicts.

        State dicts are expected to contain fields such as ``balance``,
        ``privilege``, ``resource_count``, ``quantity`` etc.
        """
        findings: list[dict[str, Any]] = []
        comparable_keys = {
            "balance",
            "privilege",
            "privilege_level",
            "resource_count",
            "resources",
            "quantity",
            "qty",
            "credits",
            "remaining",
            "wallet",
            "amount",
        }
        shared_keys = comparable_keys & set(actor_a_state) & set(actor_b_state)
        for key in sorted(shared_keys):
            a_val = actor_a_state.get(key)
            b_val = actor_b_state.get(key)
            if isinstance(a_val, (int, float)) and isinstance(b_val, (int, float)):
                if a_val != b_val:
                    change_a = a_val - b_val
                    findings.append(
                        {
                            "type": "actor_state_divergence",
                            "field": key,
                            "actor_a_value": a_val,
                            "actor_b_value": b_val,
                            "delta": change_a,
                            "privilege_leak": (
                                "actor_a_advantage"
                                if change_a > 0
                                and key in {"balance", "credits", "amount", "wallet"}
                                else "actor_b_advantage"
                                if change_a < 0
                                else None
                            ),
                        }
                    )
            elif isinstance(a_val, str) and isinstance(b_val, str) and a_val != b_val:
                lower_a = a_val.lower()
                lower_b = b_val.lower()
                privilege_order = {"user": 0, "member": 1, "premium": 2, "moderator": 3, "admin": 4}
                if key in {"privilege", "privilege_level", "role"}:
                    rank_a = privilege_order.get(lower_a, -1)
                    rank_b = privilege_order.get(lower_b, -1)
                    if rank_a != rank_b:
                        findings.append(
                            {
                                "type": "privilege_escalation_race",
                                "field": key,
                                "actor_a_value": a_val,
                                "actor_b_value": b_val,
                                "actor_a_rank": rank_a,
                                "actor_b_rank": rank_b,
                            }
                        )
        return findings

    def test_double_submit(
        self,
        actor_a: dict[str, Any],
        actor_b: dict[str, Any],
        payment_auth_id: str,
        url_template: str,
    ) -> list[dict[str, Any]]:
        """Classic double-submit race: both actors submit the same ``payment_auth_id``.

        Both actors attempt to claim the same payment authorization in parallel.
        If the backend fails to atomically de-queue the payment, one or both
        requests may succeed.
        """
        url = url_template.format(payment_auth_id=payment_auth_id)
        findings: list[dict[str, Any]] = []

        def _submit(actor: dict[str, Any]) -> dict[str, Any] | None:
            client = self._make_client(actor)
            try:
                with client:
                    resp = client.post(url, json={"payment_auth_id": payment_auth_id})
                return {
                    "status_code": resp.status_code,
                    "body_text": resp.text,
                    "headers": dict(resp.headers),
                    "actor": actor.get("actor_name", "unknown"),
                }
            except Exception as exc:  # noqa: BLE001
                return {"status_code": None, "body_text": None, "error": str(exc)}

        if httpx is None:
            raise ImportError("httpx is required for ActorRaceTester.")

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        async def _double_submit_coro() -> list[dict[str, Any]]:
            results = await asyncio.gather(
                asyncio.to_thread(_submit, actor_a),
                asyncio.to_thread(_submit, actor_b),
                return_exceptions=False,
            )
            return [r for r in results if r is not None]

        if loop is not None and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(_double_submit_coro(), loop)
            responses = future.result(timeout=60)
        else:
            responses = asyncio.run(_double_submit_coro())

        successes = [r for r in responses if r.get("status_code", 0) < 400]
        if len(successes) > 1:
            findings.append(
                {
                    "type": "double_submit_race",
                    "payment_auth_id": payment_auth_id,
                    "successful_claims": len(successes),
                    "responses": successes,
                    "risk": (
                        "Both actors successfully claimed the same payment_auth_id "
                        "indicating a double-submit race vulnerability."
                    ),
                }
            )
        elif len(successes) == 1:
            findings.append(
                {
                    "type": "possible_double_submit_race",
                    "payment_auth_id": payment_auth_id,
                    "successful_claims": 1,
                    "responses": successes,
                    "risk": (
                        "Payment authorization claimed once; further testing with "
                        "additional repetitions recommended."
                    ),
                }
            )
        return findings

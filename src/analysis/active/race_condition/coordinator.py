"""RaceCoordinator for distributed race-condition probes and UDP timestamp sync."""

import asyncio
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
    logging.getLogger(__name__).warning("Failed to import httpx", exc_info=True)
    httpx = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


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
                limits=httpx.Limits(
                    max_connections=50,
                    max_keepalive_connections=10,
                ),
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
# UDP timestamp sync helpers
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
            logger.warning("Operation failed in coordinator.py: %s", exc, exc_info=True)
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
                    logger.warning("Operation failed in coordinator.py: %s", exc, exc_info=True)
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

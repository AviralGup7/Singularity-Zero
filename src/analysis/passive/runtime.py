"""Passive analysis runtime for fetching and caching HTTP responses.

Provides RequestScheduler for rate-limited request execution, ResponseCache
for memoized HTTP responses with persistence, and fetch_response() as the
primary entry point for passive analysis modules.
"""

import concurrent.futures
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import urllib3

# Shared pool manager for connection reuse (Fix Audit #5)
_HTTP_POOL = urllib3.PoolManager(
    num_pools=50,
    maxsize=10,
    block=False,
    retries=False,
    timeout=urllib3.util.Timeout(connect=10, read=10),
)

from datetime import UTC

from src.analysis.passive.patterns import TEXTUAL_CONTENT_TYPES
from src.analysis.text_utils import (
    extract_key_fields,
    json_headers,
    looks_random,
    normalize_compare_text,
    redact_value,
    redacted_snippet,
    shannon_entropy,
)
from src.core.models import DEFAULT_USER_AGENT
from src.core.utils.url_validation import is_safe_url
from src.pipeline.cache import load_cached_json, response_cache_fresh, save_cached_json
from src.pipeline.retry import RetryPolicy
from src.recon.common import normalize_url

RequestRetryPolicy = RetryPolicy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FetchResponseResult:
    record: dict[str, Any] | None
    latency_seconds: float
    status_code: int | None
    successful: bool
    retryable: bool
    exchange_id: str | None = None


class RequestScheduler:
    def __init__(
        self,
        rate_per_second: float,
        capacity: float,
        *,
        adaptive_mode: bool = False,
        max_rate_per_second: float | None = None,
        max_capacity: float | None = None,
        min_rate_per_second: float | None = None,
        latency_threshold_seconds: float = 1.5,
        increase_step: float = 0.5,
        success_window: int = 4,
        error_backoff_factor: float = 0.5,
        latency_backoff_factor: float = 0.75,
    ) -> None:
        self.rate_per_second = max(rate_per_second, 0.01)
        self.capacity = max(capacity, 1.0)
        self.adaptive_mode = adaptive_mode
        self.max_rate_per_second = max(
            self.rate_per_second,
            max_rate_per_second
            if max_rate_per_second is not None
            else max(self.rate_per_second * 3.0, self.rate_per_second + 4.0),
        )
        self.max_capacity = max(
            self.capacity,
            max_capacity
            if max_capacity is not None
            else max(self.capacity * 2.0, self.capacity + 2.0),
        )
        self.min_rate_per_second = max(
            0.1,
            min_rate_per_second
            if min_rate_per_second is not None
            else max(self.rate_per_second * 0.25, 0.25),
        )
        self.latency_threshold_seconds = max(latency_threshold_seconds, 0.1)
        self.increase_step = max(increase_step, 0.1)
        self.success_window = max(success_window, 1)
        self.error_backoff_factor = min(max(error_backoff_factor, 0.1), 0.95)
        self.latency_backoff_factor = min(max(latency_backoff_factor, 0.1), 0.99)
        self.current_rate_per_second = self.rate_per_second
        self.current_capacity = self.capacity
        self.tokens = self.current_capacity
        self.last_refill = time.monotonic()
        self._healthy_streak = 0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        loop = None
        try:
            import asyncio
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(
                    self.current_capacity, self.tokens + elapsed * self.current_rate_per_second
                )
                self.last_refill = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                deficit = 1.0 - self.tokens
                required_sleep = deficit / self.current_rate_per_second

            sleep_time = max(0.01, required_sleep)
            if loop is not None and loop.is_running():
                import threading
                loop_thread = getattr(loop, "_thread", None)
                if loop_thread is not None and threading.current_thread() != loop_thread:
                    try:
                        future = asyncio.run_coroutine_threadsafe(asyncio.sleep(sleep_time), loop)
                        future.result()
                        continue
                    except (RuntimeError, asyncio.TimeoutError, concurrent.futures.TimeoutError, OSError) as wait_exc:
                        logger.debug("Cross-thread event-loop wait failed, falling back to time.sleep: %s", wait_exc)
            time.sleep(sleep_time)

    async def acquire_async(self) -> None:
        import asyncio

        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(
                    self.current_capacity, self.tokens + elapsed * self.current_rate_per_second
                )
                self.last_refill = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                deficit = 1.0 - self.tokens
                required_sleep = deficit / self.current_rate_per_second
            await asyncio.sleep(max(0.01, required_sleep))

    def observe(
        self,
        successful: bool,
        latency_seconds: float,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        if not self.adaptive_mode:
            return
        with self._lock:
            # Handle explicit retry-after header (highest priority) (Fix Audit #31)
            if retry_after_seconds is not None and retry_after_seconds > 0:
                backoff_factor = max(0.1, 1.0 / (1.0 + retry_after_seconds))
                self.current_rate_per_second = max(
                    self.min_rate_per_second, self.current_rate_per_second * backoff_factor
                )
                self.current_capacity = max(
                    1.0, min(self.max_capacity, self.current_capacity * backoff_factor)
                )
                self.tokens = min(self.tokens, self.current_capacity)
                self._healthy_streak = 0
                return

            if successful and latency_seconds <= self.latency_threshold_seconds:
                self._healthy_streak += 1
                if self._healthy_streak < self.success_window:
                    return
                self._healthy_streak = 0
                self.current_rate_per_second = min(
                    self.max_rate_per_second, self.current_rate_per_second + self.increase_step
                )
                self.current_capacity = min(
                    self.max_capacity, self.current_capacity + max(self.increase_step / 2.0, 0.25)
                )
                self.tokens = min(self.tokens, self.current_capacity)
                return

            self._healthy_streak = 0
            if status_code == 429:
                factor = self.error_backoff_factor * 0.5
            elif not successful:
                factor = self.error_backoff_factor
            else:
                factor = self.latency_backoff_factor
            self.current_rate_per_second = max(
                self.min_rate_per_second, self.current_rate_per_second * factor
            )
            self.current_capacity = max(1.0, min(self.max_capacity, self.current_capacity * factor))
            self.tokens = min(self.tokens, self.current_capacity)


class ResponseCache:
    def __init__(
        self,
        timeout_seconds: int,
        max_bytes: int,
        max_workers: int,
        scheduler: RequestScheduler,
        persistent_cache_path: Path | None,
        cache_ttl_hours: int,
        request_retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.max_workers = max_workers
        self.scheduler = scheduler
        self.persistent_cache_path = persistent_cache_path
        self.cache_ttl_hours = cache_ttl_hours
        self.request_retry_policy = request_retry_policy or RetryPolicy()
        self._records: dict[str, dict[str, Any] | None] = {}
        # Fix Audit #6: Cache for active probes with headers/body
        self._active_records: dict[tuple, tuple[dict[str, Any] | None, float]] = {}
        self._persistent_records = (
            load_cached_json(persistent_cache_path) if persistent_cache_path else {}
        )
        self._lock = threading.Lock()
        # Fix Audit #29: Cap in-memory records to prevent exhaustion
        self._max_memory_records = 2500

    def get(self, url: str) -> dict[str, Any] | None:
        normalized = normalize_url(url)
        with self._lock:
            if normalized in self._records:
                return self._records[normalized]
            cached = self._persistent_records.get(normalized)
            if isinstance(cached, dict) and response_cache_fresh(cached, self.cache_ttl_hours):
                if len(self._records) < self._max_memory_records:
                    self._records[normalized] = cached
                return cached

        record = self._request_with_policy(normalized)
        with self._lock:
            if len(self._records) >= self._max_memory_records:
                try:
                    evict_key = next(iter(self._records))
                    self._records.pop(evict_key, None)
                except StopIteration:
                    pass
            self._records[normalized] = record
            if record is not None:
                self._persistent_records[normalized] = {**record, "cached_at_epoch": time.time()}
        return record

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        capture_forensics: bool = False,
        target_name: str | None = None,
    ) -> dict[str, Any] | None:
        normalized = normalize_url(url)

        # Fix Audit #6: Key for active probes to allow memoization of repeated identical probes
        header_key = frozenset((headers or {}).items())

        # Robust body_key parsing to distinguish empty values and prevent unhashable TypeError
        if body is None:
            body_key = None
        elif isinstance(body, (str, bytes)):
            body_key = hash(body)
        else:
            try:
                import json

                body_key = hash(json.dumps(body, sort_keys=True))
            except Exception:
                body_key = hash(str(body))

        active_key = (normalized, method.upper(), header_key, body_key)

        if method.upper() == "GET" and not headers and body is None and not capture_forensics:
            return self.get(normalized)

        with self._lock:
            if active_key in self._active_records:
                record, expiry = self._active_records[active_key]
                if time.time() <= expiry:
                    return record
                else:
                    self._active_records.pop(active_key, None)

            if len(self._active_records) >= 1000:
                now = time.time()
                expired = [
                    k
                    for k, (_, exp) in list(self._active_records.items())
                    if now > exp
                ]
                for k in expired:
                    self._active_records.pop(k, None)
                if len(self._active_records) >= 1000:
                    self._active_records.clear()

        record = self._request_with_policy(
            normalized,
            method=method,
            headers=headers,
            body=body,
            capture_forensics=capture_forensics,
            output_dir=self.persistent_cache_path.parent if self.persistent_cache_path else None,
            target_name=target_name,
        )

        with self._lock:
            now = time.time()
            expired = [k for k, (_, exp) in list(self._active_records.items()) if now > exp]
            for k in expired:
                self._active_records.pop(k, None)
            if len(self._active_records) >= 1000:
                to_remove = len(self._active_records) - 999
                oldest = sorted(
                    ((k, exp) for k, (_, exp) in self._active_records.items()),
                    key=lambda x: x[1],
                )
                for k, _ in oldest[:to_remove]:
                    self._active_records.pop(k, None)
            self._active_records[active_key] = (record, now + (self.cache_ttl_hours * 3600))

        return record

    def prefetch(self, targets: list[str]) -> list[dict[str, Any]]:
        normalized_targets = [normalize_url(target) for target in targets if normalize_url(target)]
        unique_targets = list(dict.fromkeys(normalized_targets))
        if not unique_targets:
            return []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(unique_targets))) as executor:
            results = executor.map(self.get, unique_targets)
            return [result for result in results if result]

    def persist(self) -> None:
        if self.persistent_cache_path:
            lock_path = self.persistent_cache_path.with_suffix(".lock")
            import sys
            with self._lock:
                fd = None
                try:
                    fd = open(lock_path, "w")
                    if sys.platform == "win32":
                        import msvcrt
                        msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX)
                    current_on_disk = load_cached_json(self.persistent_cache_path) if self.persistent_cache_path.exists() else {}
                    current_on_disk.update(self._persistent_records)
                    save_cached_json(self.persistent_cache_path, current_on_disk)
                except Exception as exc:
                    logger.warning("Failed to persist cache atomically: %s", exc)
                finally:
                    if fd:
                        try:
                            if sys.platform == "win32":
                                import msvcrt
                                fd.seek(0)
                                msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
                            else:
                                import fcntl
                                fcntl.flock(fd, fcntl.LOCK_UN)
                        except (OSError, ValueError) as lock_release_exc:
                            logger.debug("Lock release failed during fd cleanup: %s", lock_release_exc)
                        fd.close()

    def _request_with_policy(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        capture_forensics: bool = False,
        output_dir: Path | None = None,
        target_name: str | None = None,
    ) -> dict[str, Any] | None:
        policy = self.request_retry_policy
        last_result: FetchResponseResult | None = None

        for attempt in range(1, policy.max_attempts + 1):
            self.scheduler.acquire()
            result = _fetch_response_once(
                url,
                self.timeout_seconds,
                self.max_bytes,
                method=method,
                extra_headers=headers,
                body=body,
            )

            # Fix Audit #31: Extract Retry-After
            retry_after = 0.0
            if result.record and "headers" in result.record:
                ra = result.record["headers"].get("Retry-After")
                if ra:
                    if str(ra).isdigit():
                        retry_after = float(ra)
                    else:
                        import email.utils
                        from datetime import datetime

                        try:
                            dt = email.utils.parsedate_to_datetime(str(ra))
                            if dt:
                                retry_after = max(0.0, (dt - datetime.now(UTC)).total_seconds())
                        except Exception:  # noqa: S110
                            pass

            self.scheduler.observe(
                successful=result.successful,
                latency_seconds=result.latency_seconds,
                status_code=result.status_code,
                retry_after_seconds=retry_after,
            )

            if capture_forensics and result.record and output_dir and target_name:
                from src.analysis.passive.forensics import ForensicExchange, save_forensic_exchange

                exchange = ForensicExchange(
                    url=url,
                    method=method,
                    request_headers=headers or {},
                    request_body=body,
                    response_status=result.status_code,
                    response_headers=result.record.get("headers", {}),
                    response_body=result.record.get("body_text", ""),
                    latency_seconds=result.latency_seconds,
                )
                save_forensic_exchange(output_dir, exchange, target_name)
                result = FetchResponseResult(
                    record={**result.record, "exchange_id": exchange.exchange_id},
                    latency_seconds=result.latency_seconds,
                    status_code=result.status_code,
                    successful=result.successful,
                    retryable=result.retryable,
                    exchange_id=exchange.exchange_id,
                )

            last_result = result
            if not result.retryable or attempt >= policy.max_attempts:
                return result.record
            delay = policy.delay_for_attempt(attempt + 1)
            if delay > 0:
                time.sleep(delay)
        return last_result.record if last_result else None


def _fetch_response_stream(
    url: str,
    timeout_seconds: int,
    max_bytes: int,
    *,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
) -> dict[str, Any] | None:
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    request_body: bytes | None = body.encode("utf-8") if isinstance(body, str) else body
    if request_body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    resp = None
    try:
        resp = _HTTP_POOL.request(
            method.upper(),
            url,
            headers=headers,
            body=request_body,
            preload_content=False,
            redirect=True,
            timeout=urllib3.util.Timeout(connect=timeout_seconds, read=timeout_seconds),
        )

        redirect_history = getattr(resp, "redirect_history", None) or []
        redirect_count = len(redirect_history)
        redirect_chain = [normalize_url(url)]
        if redirect_history:
            for entry in redirect_history:
                redirect_chain.append(normalize_url(entry.redirect_url))
        final_url = normalize_url(getattr(resp, "geturl", lambda: url)() or url)

        resp_headers = dict(resp.headers.items())
        content_type = resp_headers.get("Content-Type", "")
        body_parts: list[bytes] = []
        bytes_read = 0
        chunk_size = 8192
        truncated = False

        while True:
            chunk = resp.read(chunk_size)
            if not chunk:
                break
            remaining = max_bytes - bytes_read
            if remaining <= 0:
                truncated = True
                break
            if len(chunk) > remaining:
                body_parts.append(chunk[:remaining])
                bytes_read += remaining
                truncated = True
            else:
                body_parts.append(chunk)
                bytes_read += len(chunk)

        body_text = ""
        raw = b"".join(body_parts)
        if is_textual_content_type(content_type) and raw:
            charset = extract_charset(content_type)
            try:
                body_text = raw.decode(charset, errors="replace")
            except LookupError:
                body_text = raw.decode("utf-8", errors="replace")

        return {
            "requested_url": normalize_url(url),
            "request_method": method.upper(),
            "url": final_url,
            "final_url": final_url,
            "status_code": resp.status,
            "headers": resp_headers,
            "content_type": content_type,
            "body_text": body_text,
            "body_length": len(body_text),
            "truncated": truncated,
            "redirect_chain": redirect_chain,
            "redirect_count": redirect_count,
        }
    except Exception as exc:
        logger.debug("Streaming error fetching %s: %s", url, exc)
        return None
    finally:
        if resp is not None:
            try:
                resp.release_conn()
            except (OSError, AttributeError, RuntimeError) as release_exc:
                logger.debug("urllib3 response.release_conn() failed: %s", release_exc)


def fetch_response(
    url: str,
    timeout_seconds: int,
    max_bytes: int,
    *,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    stream: bool = False,
    capture_forensics: bool = False,
    output_dir: Path | None = None,
    target_name: str | None = None,
) -> dict[str, Any] | None:
    if stream:
        return _fetch_response_stream(
            url, timeout_seconds, max_bytes, method=method, extra_headers=extra_headers, body=body
        )

    result = _fetch_response_once(
        url, timeout_seconds, max_bytes, method=method, extra_headers=extra_headers, body=body
    )
    if capture_forensics and result.record and output_dir and target_name:
        from src.analysis.passive.forensics import ForensicExchange, save_forensic_exchange

        exchange = ForensicExchange(
            url=url,
            method=method,
            request_headers=extra_headers or {},
            request_body=body,
            response_status=result.status_code,
            response_headers=result.record.get("headers", {}),
            response_body=result.record.get("body_text", ""),
            latency_seconds=result.latency_seconds,
        )
        save_forensic_exchange(output_dir, exchange, target_name)
        return {**result.record, "exchange_id": exchange.exchange_id}

    return result.record


def _fetch_response_once(
    url: str,
    timeout_seconds: int,
    max_bytes: int,
    *,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
) -> FetchResponseResult:
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    request_body: bytes | None = body.encode("utf-8") if isinstance(body, str) else body
    if request_body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    if not is_safe_url(url):
        return FetchResponseResult(None, 0.0, None, False, False)

    started_at = time.monotonic()
    try:
        # Fix Audit #5: Use shared pool for connection reuse
        response = _HTTP_POOL.request(
            method.upper(),
            url,
            headers=headers,
            body=request_body,
            preload_content=True,
            timeout=urllib3.util.Timeout(connect=timeout_seconds, read=timeout_seconds),
        )

        latency = time.monotonic() - started_at
        # Fix Audit #7: Include response_time_ms
        record = build_response_record(
            url, response, max_bytes, request_method=method.upper(), latency_ms=latency * 1000
        )

        status_code = int(record.get("status_code") or 0)
        successful = status_code < 400
        retryable = status_code == 429 or 500 <= status_code < 600

        return FetchResponseResult(
            record=record,
            latency_seconds=latency,
            status_code=status_code,
            successful=successful,
            retryable=retryable,
        )
    except urllib3.exceptions.HTTPError as exc:
        logger.debug("Error fetching %s: %s", url, exc)
        return FetchResponseResult(None, time.monotonic() - started_at, None, False, True)
    except Exception as exc:
        logger.warning("Unexpected error fetching %s: %s", url, exc, exc_info=True)
        raise


def build_response_record(
    url: str, response: Any, max_bytes: int, *, request_method: str = "GET", latency_ms: float = 0.0
) -> dict[str, Any]:
    headers = dict(response.headers.items())
    content_type = headers.get("Content-Type", "")
    body_text = ""
    raw = b""
    if max_bytes > 0:
        if getattr(response, "data", None):
            raw = response.data
        else:
            raw = response.read(max_bytes + 1)
    if is_textual_content_type(content_type) and raw:
        charset = extract_charset(content_type)
        try:
            body_text = raw[:max_bytes].decode(charset, errors="replace")
        except LookupError:
            body_text = raw[:max_bytes].decode("utf-8", errors="replace")

    status_code = getattr(response, "status", None) or getattr(response, "code", None)
    final_url = normalize_url(getattr(response, "geturl", lambda: url)() or url)
    return {
        "requested_url": normalize_url(url),
        "request_method": request_method,
        "url": final_url,
        "final_url": final_url,
        "status_code": status_code,
        "headers": headers,
        "content_type": content_type,
        "body_text": body_text,
        "body_length": len(body_text),
        "truncated": len(raw) > max_bytes if max_bytes > 0 else False,
        "redirect_chain": [normalize_url(url), final_url]
        if final_url != normalize_url(url)
        else [normalize_url(url)],
        "redirect_count": 1 if final_url != normalize_url(url) else 0,
        "response_time_ms": round(latency_ms, 2),  # Fix Audit #7
    }


def is_textual_content_type(content_type: str) -> bool:
    normalized = content_type.lower()
    return any(normalized.startswith(prefix) for prefix in TEXTUAL_CONTENT_TYPES)


def extract_charset(content_type: str) -> str:
    if "charset=" not in content_type.lower():
        return "utf-8"
    return content_type.split("charset=", 1)[1].split(";", 1)[0].strip() or "utf-8"


__all__ = [
    "FetchResponseResult",
    "RequestScheduler",
    "ResponseCache",
    "fetch_response",
    "extract_key_fields",
    "normalize_compare_text",
    "redact_value",
    "json_headers",
    "looks_random",
    "redacted_snippet",
    "shannon_entropy",
]

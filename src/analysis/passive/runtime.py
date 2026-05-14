"""Passive analysis runtime for fetching and caching HTTP responses.

Provides RequestScheduler for rate-limited request execution, ResponseCache
for memoized HTTP responses with persistence, and fetch_response() as the
primary entry point for passive analysis modules.
"""

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError

import urllib3

from src.analysis.passive.patterns import TEXTUAL_CONTENT_TYPES
from src.core.models import DEFAULT_USER_AGENT
from src.core.utils.url_validation import is_safe_url
from src.pipeline.cache import load_cached_json, response_cache_fresh, save_cached_json
from src.pipeline.retry import RetryPolicy
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)


RequestRetryPolicy = RetryPolicy


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
            time.sleep(0.05)

    def observe(
        self,
        *,
        successful: bool,
        latency_seconds: float,
        status_code: int | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        if not self.adaptive_mode:
            return
        with self._lock:
            # Handle explicit retry-after header (highest priority)
            if retry_after_seconds is not None and retry_after_seconds > 0:
                # Immediately reduce rate based on retry-after duration
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
            # 429 rate limit responses get stronger backoff
            if status_code == 429:
                factor = self.error_backoff_factor * 0.5  # Stronger backoff for rate limits
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
        self._persistent_records = (
            load_cached_json(persistent_cache_path) if persistent_cache_path else {}
        )
        self._lock = threading.Lock()

    def get(self, url: str) -> dict[str, Any] | None:
        normalized = normalize_url(url)
        with self._lock:
            if normalized in self._records:
                return self._records[normalized]
            cached = self._persistent_records.get(normalized)
            if isinstance(cached, dict) and response_cache_fresh(cached, self.cache_ttl_hours):
                self._records[normalized] = cached
                return cached

        record = self._request_with_policy(normalized)
        with self._lock:
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
        # Cache only plain GET requests; active probes should bypass memoization.
        if method.upper() == "GET" and not headers and body is None and not capture_forensics:
            return self.get(normalized)
        return self._request_with_policy(
            normalized,
            method=method,
            headers=headers,
            body=body,
            capture_forensics=capture_forensics,
            output_dir=self.persistent_cache_path.parent if self.persistent_cache_path else None,
            target_name=target_name,
        )

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
            save_cached_json(self.persistent_cache_path, self._persistent_records)

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
        last_result: FetchResponseResult | None = None
        for attempt in range(1, self.request_retry_policy.max_attempts + 1):
            self.scheduler.acquire()
            result = _fetch_response_once(
                url,
                self.timeout_seconds,
                self.max_bytes,
                method=method,
                extra_headers=headers,
                body=body,
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
                # Update result with exchange_id
                result = FetchResponseResult(
                    record={**result.record, "exchange_id": exchange.exchange_id},
                    latency_seconds=result.latency_seconds,
                    status_code=result.status_code,
                    successful=result.successful,
                    retryable=result.retryable,
                    exchange_id=exchange.exchange_id,
                )

            last_result = result
            self.scheduler.observe(
                successful=result.successful,
                latency_seconds=result.latency_seconds,
                status_code=result.status_code,
            )
            if not result.retryable or attempt >= self.request_retry_policy.max_attempts:
                return result.record
            delay = self.request_retry_policy.delay_for_attempt(attempt + 1)
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
    """Fetch a response using streaming chunked reading."""
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    request_body: bytes | None = body.encode("utf-8") if isinstance(body, str) else body
    if request_body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"

    pool = urllib3.PoolManager(
        num_pools=1,
        maxsize=1,
        timeout=urllib3.util.Timeout(connect=timeout_seconds, read=timeout_seconds),
    )

    try:
        resp = pool.request(
            method.upper(),
            url,
            headers=headers,
            body=request_body,
            preload_content=False,
            redirect=True,
        )

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

        resp.release_conn()
        body_text = ""
        raw = b"".join(body_parts)
        if is_textual_content_type(content_type) and raw:
            charset = extract_charset(content_type)
            try:
                body_text = raw.decode(charset, errors="replace")
            except LookupError:
                body_text = raw.decode("utf-8", errors="replace")

        final_url = normalize_url(url)
        redirect_chain = [normalize_url(url)]

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
            "redirect_count": 0,
        }
    except Exception as exc:
        logger.debug("Streaming error fetching %s: %s", url, exc)
        return None
    finally:
        pool.clear()


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
            url,
            timeout_seconds,
            max_bytes,
            method=method,
            extra_headers=extra_headers,
            body=body,
        )

    result = _fetch_response_once(
        url,
        timeout_seconds,
        max_bytes,
        method=method,
        extra_headers=extra_headers,
        body=body,
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
    # Encode body if needed
    request_body: bytes | None = body.encode("utf-8") if isinstance(body, str) else body
    if request_body and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    if not is_safe_url(url):
        logger.debug("URL failed safety check: %s", url)
        return FetchResponseResult(
            record=None,
            latency_seconds=0.0,
            status_code=None,
            successful=False,
            retryable=False,
        )
    started_at = time.monotonic()
    try:
        pool = urllib3.PoolManager(
            num_pools=1,
            maxsize=1,
            timeout=urllib3.util.Timeout(connect=timeout_seconds, read=timeout_seconds),
        )
        response = pool.request(
            method.upper(), url, headers=headers, body=request_body, preload_content=True
        )
        record = build_response_record(url, response, max_bytes, request_method=method.upper())
        status_code = int(record.get("status_code") or 0)
        retryable = status_code == 429 or 500 <= status_code < 600
        successful = status_code < 400
        return FetchResponseResult(
            record=record,
            latency_seconds=time.monotonic() - started_at,
            status_code=status_code,
            successful=successful,
            retryable=retryable,
        )
    except (TimeoutError, URLError) as exc:
        logger.debug("Ignoring timeout error for %s: %s", url, exc)
        return FetchResponseResult(
            record=None,
            latency_seconds=time.monotonic() - started_at,
            status_code=None,
            successful=False,
            retryable=True,
        )
    except Exception as exc:
        logger.debug("Unexpected error fetching %s: %s", url, exc)
        return FetchResponseResult(
            record=None,
            latency_seconds=time.monotonic() - started_at,
            status_code=None,
            successful=False,
            retryable=False,
        )


def build_response_record(
    url: str, response: Any, max_bytes: int, *, request_method: str = "GET"
) -> dict[str, Any]:
    headers = dict(response.headers.items())
    content_type = headers.get("Content-Type", "")
    body_text = ""
    raw = b""
    if max_bytes > 0:
        raw = response.read(max_bytes + 1)
    if is_textual_content_type(content_type) and raw:
        charset = extract_charset(content_type)
        try:
            body_text = raw[:max_bytes].decode(charset, errors="replace")
        except LookupError:
            body_text = raw[:max_bytes].decode("utf-8", errors="replace")

    status_code = getattr(response, "status", None) or getattr(response, "code", None)
    final_url = normalize_url(getattr(response, "geturl", lambda: url)() or url)
    redirect_chain = [normalize_url(url)]
    if final_url and final_url != redirect_chain[0]:
        redirect_chain.append(final_url)
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
        "redirect_chain": redirect_chain,
        "redirect_count": max(len(redirect_chain) - 1, 0),
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

from src.analysis.text_utils import (
    extract_key_fields,
    json_headers,
    looks_random,
    normalize_compare_text,
    redact_value,
    redacted_snippet,
    shannon_entropy,
)

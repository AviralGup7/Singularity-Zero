"""HTTP client and configuration for validation probes."""

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from src.analysis.passive.runtime import fetch_response
from src.pipeline.retry import RetryPolicy


@dataclass(frozen=True)
class ValidationHttpConfig:
    timeout_seconds: int
    max_response_bytes: int
    retry_policy: RetryPolicy


class ValidationHttpClient:
    """Thread-safe HTTP client for validation probes that reuses the pipeline fetch client."""

    _MAX_CACHE_ITEMS = 256

    def __init__(self, config: ValidationHttpConfig) -> None:
        self.config = config
        self._response_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._cache_lock = threading.Lock()

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        with self._cache_lock:
            value = self._response_cache.get(key)
            if value is None:
                return None
            self._response_cache.move_to_end(key)
            return value

    def _cache_set(self, key: str, value: dict[str, Any]) -> None:
        with self._cache_lock:
            self._response_cache[key] = value
            self._response_cache.move_to_end(key)
            while len(self._response_cache) > self._MAX_CACHE_ITEMS:
                self._response_cache.popitem(last=False)

    def request(
        self, url: str, *, method: str = "GET", headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        cache_key = f"{method}:{url}:{sorted((headers or {}).items())}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        started = time.monotonic()
        last_error = "request_failed"
        for attempt in range(1, self.config.retry_policy.max_attempts + 1):
            try:
                record = fetch_response(
                    url,
                    self.config.timeout_seconds,
                    self.config.max_response_bytes,
                    method=method,
                    extra_headers=headers,
                )
            except Exception as exc:
                record = None
                last_error = f"exception:{exc.__class__.__name__}"
            else:
                if record is not None:
                    status_code = int(record.get("status_code") or 0)
                    retryable = status_code == 429 or 500 <= status_code < 600
                    if not retryable:
                        result = {
                            "ok": True,
                            "requested_url": record.get("requested_url", url),
                            "final_url": record.get("final_url", record.get("url", url)),
                            "status_code": record.get("status_code"),
                            "redirect_count": record.get("redirect_count", 0),
                            "body_length": record.get("body_length", 0),
                            "attempts": attempt,
                            "timeout_seconds": self.config.timeout_seconds,
                            "latency_seconds": round(time.monotonic() - started, 3),
                            "error": "",
                        }
                        self._cache_set(cache_key, result)
                        return result
                    last_error = f"retryable_status:{status_code}"
                else:
                    last_error = "timeout_or_network"
            if attempt < self.config.retry_policy.max_attempts:
                delay = self.config.retry_policy.delay_for_attempt(attempt)
                if delay > 0:
                    time.sleep(delay)

        result = {
            "ok": False,
            "requested_url": url,
            "final_url": url,
            "status_code": None,
            "redirect_count": 0,
            "body_length": 0,
            "attempts": self.config.retry_policy.max_attempts,
            "timeout_seconds": self.config.timeout_seconds,
            "latency_seconds": round(time.monotonic() - started, 3),
            "error": last_error,
        }
        self._cache_set(cache_key, result)
        return result

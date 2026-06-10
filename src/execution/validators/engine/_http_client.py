"""HTTP client and configuration for validation probes."""

import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from src.pipeline.retry import RetryPolicy

logger = logging.getLogger(__name__)

# Module-level reference to ``fetch_response``. Tests patch this attribute
# via ``patch.object(_http_client, "fetch_response", ...)`` so the symbol
# must be present on the module. We bind it lazily on first access via
# ``_resolve_fetch_response`` to avoid the circular import that would
# occur if we imported ``src.analysis.passive.runtime`` at module load.
fetch_response = None  # type: ignore[assignment]

# Headers whose values must be included in the cache key (R-fix) to
# prevent the same URL with different credentials from being shared
# across probes.
_AUTH_HEADERS: frozenset[str] = frozenset(
    {"authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization"}
)


@dataclass(frozen=True)
class ValidationHttpConfig:
    timeout_seconds: int
    max_response_bytes: int
    retry_policy: RetryPolicy


def _cache_key_for(method: str, url: str, headers: dict[str, str] | None, body: Any) -> str:
    """Return a stable cache key for an HTTP probe.

    Includes normalized ``Authorization``/``Cookie`` (Bug G fix) and a
    short fingerprint of the body so different credentials or bodies do
    not share cached responses.
    """
    normalized: list[tuple[str, str]] = []
    for key, value in sorted((headers or {}).items(), key=lambda item: item[0].lower()):
        if key.lower() in _AUTH_HEADERS:
            normalized.append((key.lower(), str(value)))
    if body is None:
        body_fp = ""
    elif isinstance(body, (bytes, bytearray)):
        body_fp = f"bytes:{len(body)}"
    else:
        body_str = str(body)
        body_fp = f"str:{len(body_str)}:{body_str[:64]}"
    return f"{method.upper()}:{url}:{normalized}:{body_fp}"


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
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        return_body: bool = False,
    ) -> dict[str, Any]:
        """Perform an HTTP request via the shared fetch client.

        Args:
            url: Target URL.
            method: HTTP method.
            headers: Optional request headers.
            body: Optional request body (str or bytes).
            return_body: When True, include the response body in the
                returned dict (used by race/cache/JWT probes).
        """
        fetch_response = _resolve_fetch_response()

        cache_key = _cache_key_for(method, url, headers, body)
        cached = self._cache_get(cache_key)
        if cached is not None:
            if return_body and "body" not in cached:
                cached = dict(cached)
                cached["body"] = str(cached.get("body_text", "") or "")
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
                    body=body,
                )
            except Exception as exc:
                record = None
                last_error = f"exception:{exc.__class__.__name__}"
            else:
                if record is not None:
                    status_code = int(record.get("status_code") or 0)
                    retryable = status_code == 429 or 500 <= status_code < 600
                    if not retryable:
                        body_text = str(record.get("body_text", "") or "")
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
                            "headers": dict(record.get("headers") or {}),
                            "body": body_text if return_body else "",
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
            "headers": {},
            "body": "" if return_body else "",
        }
        self._cache_set(cache_key, result)
        return result

    # R7 probe helpers ---------------------------------------------------
    def jwt_probe(self, token: str, target_url: str) -> dict[str, Any]:
        """Send a JWT candidate to ``target_url`` and return a probe dict."""
        if not target_url:
            return {"status_code": 0, "body": "", "headers": {}}
        parsed = urlparse(target_url)
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }
        response = self.request(
            target_url,
            method="GET",
            headers=headers,
            return_body=True,
        )
        return {
            "status_code": response.get("status_code", 0),
            "body": response.get("body", ""),
            "headers": response.get("headers", {}) or {},
            "scheme": parsed.scheme,
        }

    def graphql_probe(self, endpoint: str, query: str) -> dict[str, Any]:
        """POST a GraphQL query and return the response."""
        body = str(query or "")
        response = self.request(
            endpoint,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body=body,
            return_body=True,
        )
        return {
            "status_code": response.get("status_code", 0),
            "body": response.get("body", ""),
            "headers": response.get("headers", {}) or {},
        }

    def cache_poison_probe(self, target_url: str, unkeyed_header: str) -> dict[str, Any]:
        """Send a cache poisoning probe (R7) and return both responses."""
        import uuid

        token = f"cacheprobe-{uuid.uuid4().hex[:16]}"
        probe = self.request(
            target_url,
            method="GET",
            headers={unkeyed_header: token},
            return_body=True,
        )
        followup = self.request(target_url, method="GET", return_body=True)
        return {
            "probe_response": {
                "status_code": probe.get("status_code", 0),
                "headers": probe.get("headers", {}) or {},
                "body": probe.get("body", ""),
                "probe_token": token,
            },
            "followup_response": {
                "status_code": followup.get("status_code", 0),
                "headers": followup.get("headers", {}) or {},
                "body": followup.get("body", ""),
            },
        }

    def race_probe(self, target_url: str, *, concurrency: int = 5) -> list[dict[str, Any]]:
        """Send ``concurrency`` concurrent requests to ``target_url``."""
        from concurrent.futures import ThreadPoolExecutor

        responses: list[dict[str, Any]] = []

        def _single() -> dict[str, Any]:
            response = self.request(target_url, method="GET", return_body=True)
            return {
                "status_code": response.get("status_code", 0),
                "body": response.get("body", ""),
                "headers": response.get("headers", {}) or {},
            }

        if concurrency <= 0:
            return responses
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(_single) for _ in range(concurrency)]
            for future in futures:
                try:
                    responses.append(future.result(timeout=30) or {})
                except Exception as exc:  # noqa: BLE001 — broad catch intentional for concurrent future isolation
                    logger.debug("Race probe concurrent request failed: %s", exc)
                    responses.append({"status_code": 0, "body": "", "headers": {}})
        return responses


def _resolve_fetch_response() -> Any:
    """Return the ``fetch_response`` callable to use for HTTP probing.

    Tests patch ``src.execution.validators.engine._http_client.fetch_response``
    on this module, so we look the symbol up here at call time. If the
    symbol is still the lazy ``None`` placeholder (i.e. a test has not
    patched it) we fall back to the real implementation lazily, which
    prevents the circular import that would occur if we imported it at
    module top level.
    """
    fn = globals().get("fetch_response")
    if fn is None:
        from src.analysis.passive.runtime import fetch_response as _fn

        globals()["fetch_response"] = _fn
        return _fn
    return fn

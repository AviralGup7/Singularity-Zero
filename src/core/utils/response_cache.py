"""In-memory response cache with optional persistence.

A self-contained ``ResponseCache`` for use in execution-layer child
processes where ``persistent_cache_path`` is ``None`` and no pipeline
imports are needed.  When persistence or prefetch is required, the full
analysis-layer ``ResponseCache`` should be used instead.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.core.utils import normalize_url
from src.core.utils.scheduler import RequestScheduler

logger = logging.getLogger(__name__)


class ResponseCache:
    """Minimal in-memory response cache (core-only, no pipeline deps).

    When *persistent_cache_path* is ``None`` (the typical child-process
    case) the cache operates purely in memory and does not touch any
    pipeline modules, keeping the import graph clean.
    """

    def __init__(
        self,
        timeout_seconds: int,
        max_bytes: int,
        max_workers: int,
        scheduler: RequestScheduler,
        persistent_cache_path: Path | None,
        cache_ttl_hours: int,
        *,
        request_retry_policy: Any | None = None,
        load_cached_json: Callable[..., Any] | None = None,
        save_cached_json: Callable[..., Any] | None = None,
        response_cache_fresh: Callable[..., Any] | None = None,
        get_shared_executor: Callable[..., Any] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.max_workers = max_workers
        self.scheduler = scheduler
        self.persistent_cache_path = persistent_cache_path
        self.cache_ttl_hours = cache_ttl_hours
        self.request_retry_policy = request_retry_policy
        self._records: dict[str, dict[str, Any] | None] = {}
        self._active_records: dict[tuple, tuple[dict[str, Any] | None, float]] = {}
        self._persistent_records: dict[str, Any] = {}
        self._load_cached_json = load_cached_json
        self._save_cached_json = save_cached_json
        self._response_cache_fresh = response_cache_fresh
        self._get_shared_executor = get_shared_executor
        if persistent_cache_path is not None and load_cached_json is not None:
            loaded = load_cached_json(persistent_cache_path)
            if isinstance(loaded, dict):
                self._persistent_records = loaded
        self._lock = threading.Lock()
        self._max_memory_records = 2500

    def get(self, url: str) -> dict[str, Any] | None:
        normalized = normalize_url(url)
        with self._lock:
            if normalized in self._records:
                return self._records[normalized]
            cached = self._persistent_records.get(normalized)
            if (
                isinstance(cached, dict)
                and self._response_cache_fresh is not None
                and self._response_cache_fresh(cached, self.cache_ttl_hours)
            ):
                if len(self._records) < self._max_memory_records:
                    self._records[normalized] = cached
                return cached
        return None

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | bytes | None = None,
        capture_forensics: bool = False,
        target_name: str | None = None,
        auth_override: Any | None = None,
    ) -> dict[str, Any] | None:
        normalized = normalize_url(url)
        merged_headers = dict(headers or {})
        if auth_override is not None:
            merged_headers.update(auth_override.get_headers_for_url(normalized))
        header_key = frozenset(merged_headers.items())

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

        if (
            method.upper() == "GET"
            and not merged_headers
            and body is None
            and not capture_forensics
        ):
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
                expired = [k for k, (_, exp) in list(self._active_records.items()) if now > exp]
                for k in expired:
                    self._active_records.pop(k, None)
                if len(self._active_records) >= 1000:
                    self._active_records.clear()

        return None

    def prefetch(self, targets: list[str]) -> list[dict[str, Any]]:
        normalized_targets = [normalize_url(target) for target in targets if normalize_url(target)]
        unique_targets = list(dict.fromkeys(normalized_targets))
        if not unique_targets:
            return []
        if self._get_shared_executor is not None:
            executor = self._get_shared_executor()
            results = executor.map(self.get, unique_targets)
            return [result for result in results if result]
        return [r for r in (self.get(t) for t in unique_targets) if r]

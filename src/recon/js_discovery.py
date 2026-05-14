"""JS endpoint discovery helpers extracted from urls.py.

This module contains the logic for fetching HTML/JS, extracting
script references and candidate endpoints, and running discovery across
hosts in parallel. It mirrors the behaviour previously embedded in
`src.recon.urls` but keeps the surface small for easier testing and
reuse.
"""

from __future__ import annotations

import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Any

from src.core.models import Config
from src.recon.collectors.observability import emit_collection_progress
from src.recon.js_fetcher import _fetch_text_content
from src.recon.js_parsers import (
    _extract_js_candidate_urls,
    _extract_script_urls_from_html,
    _normalized_scope_roots,
)


def _collect_js_discovery_urls(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    runtime_budget_seconds: int | None = None,
) -> tuple[set[str], dict[str, Any]]:
    filters = config.filters or {}
    if not bool(filters.get("js_discovery_enabled", True)):
        return set(), {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}

    max_hosts = max(1, int(filters.get("js_discovery_max_hosts", 25) or 25))
    workers = max(1, int(filters.get("js_discovery_workers", 8) or 8))
    timeout_seconds = max(2, int(filters.get("js_discovery_timeout_seconds", 8) or 8))
    max_js_files_per_host = max(
        1,
        int(filters.get("js_discovery_max_js_files_per_host", 12) or 12),
    )
    max_discovered_urls = max(
        50,
        int(filters.get("js_discovery_max_urls", 2000) or 2000),
    )
    max_response_bytes = max(
        4096,
        int(filters.get("js_discovery_max_response_bytes", 250000) or 250000),
    )
    js_discovery_time_budget_seconds = max(
        1,
        int(filters.get("js_discovery_time_budget_seconds", 180) or 180),
    )
    if runtime_budget_seconds is not None:
        js_discovery_time_budget_seconds = max(
            1,
            min(js_discovery_time_budget_seconds, int(runtime_budget_seconds)),
        )

    scoped_hosts = sorted({host for host in live_hosts if host})[:max_hosts]
    if not scoped_hosts:
        return set(), {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}

    scope_roots = _normalized_scope_roots(scope_entries)
    started = time.monotonic()
    discovered_urls: set[str] = set()
    hosts_scanned = 0
    script_refs = 0
    js_files_fetched = 0
    errors = 0
    budget_exceeded = False

    def _scan_single_host(base_url: str) -> tuple[set[str], int, int]:
        host_discovered: set[str] = set()
        html = _fetch_text_content(base_url, timeout_seconds, max_response_bytes)
        if not html:
            return host_discovered, 0, 0

        host_discovered.update(_extract_js_candidate_urls(html, base_url, scope_roots))
        script_urls = sorted(_extract_script_urls_from_html(html, base_url, scope_roots))
        fetched = 0
        for js_url in script_urls[:max_js_files_per_host]:
            js_body = _fetch_text_content(js_url, timeout_seconds, max_response_bytes)
            if not js_body:
                continue
            fetched += 1
            host_discovered.update(_extract_js_candidate_urls(js_body, js_url, scope_roots))
        host_discovered.update(script_urls[:max_js_files_per_host])
        return host_discovered, len(script_urls), fetched

    emit_collection_progress(
        progress_callback,
        f"Running JS endpoint discovery across {len(scoped_hosts)} hosts",
        65,
    )
    max_workers = min(workers, len(scoped_hosts))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        pending: dict[Any, str] = {}
        submitted = 0

        while submitted < len(scoped_hosts) and len(pending) < max_workers:
            host = scoped_hosts[submitted]
            pending[executor.submit(_scan_single_host, host)] = host
            submitted += 1

        while pending:
            elapsed = time.monotonic() - started
            if elapsed >= js_discovery_time_budget_seconds:
                budget_exceeded = True
                for future in pending:
                    future.cancel()
                emit_collection_progress(
                    progress_callback,
                    (
                        "JS endpoint discovery budget exceeded "
                        f"({elapsed:.1f}s/{js_discovery_time_budget_seconds}s); "
                        "continuing with discovered URLs so far"
                    ),
                    66,
                    processed=hosts_scanned,
                    total=len(scoped_hosts),
                    stage_percent=int((hosts_scanned / max(1, len(scoped_hosts))) * 100),
                )
                break

            done, _ = wait(list(pending), timeout=0.2, return_when=FIRST_COMPLETED)
            if not done:
                continue

            for future in done:
                pending.pop(future, None)
                try:
                    host_urls, host_script_refs, host_js_files = future.result()
                except Exception:
                    host_urls, host_script_refs, host_js_files = set(), 0, 0
                    errors += 1
                hosts_scanned += 1
                script_refs += host_script_refs
                js_files_fetched += host_js_files
                before = len(discovered_urls)
                discovered_urls.update(host_urls)
                if max_discovered_urls > 0 and len(discovered_urls) > max_discovered_urls:
                    prioritized = sorted(discovered_urls, key=lambda item: ("?" not in item, item))
                    discovered_urls = set(prioritized[:max_discovered_urls])
                emit_collection_progress(
                    progress_callback,
                    (
                        f"js discovery host {hosts_scanned}/{len(scoped_hosts)}: "
                        f"+{max(0, len(discovered_urls) - before)} URLs, total {len(discovered_urls)}"
                    ),
                    66,
                    processed=hosts_scanned,
                    total=len(scoped_hosts),
                    stage_percent=int((hosts_scanned / max(1, len(scoped_hosts))) * 100),
                )

                if submitted >= len(scoped_hosts):
                    continue
                if time.monotonic() - started >= js_discovery_time_budget_seconds:
                    continue

                host = scoped_hosts[submitted]
                pending[executor.submit(_scan_single_host, host)] = host
                submitted += 1

    meta = {
        "status": "degraded_timeout" if budget_exceeded else ("ok" if discovered_urls else "empty"),
        "duration_seconds": round(time.monotonic() - started, 1),
        "new_urls": len(discovered_urls),
        "hosts_scanned": hosts_scanned,
        "script_refs": script_refs,
        "js_files_fetched": js_files_fetched,
        "errors": errors,
        "js_discovery_time_budget_seconds": js_discovery_time_budget_seconds,
        "budget_exceeded": budget_exceeded,
    }
    return discovered_urls, meta


__all__ = ["_collect_js_discovery_urls"]

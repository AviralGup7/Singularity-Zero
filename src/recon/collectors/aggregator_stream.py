"""Streaming aggregator for providers.

Yields URLs as providers produce results. This is an incremental,
non-blocking (per provider) streaming model that keeps memory usage
bounded and allows downstream consumers to process results while
collection is still ongoing.
"""

from __future__ import annotations

import time
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from src.core.models.config import Config
from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.providers import commoncrawl, crawler, otx, urlscan, wayback


def collect_urls_stream(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    stage_meta: dict[str, Any] | None = None,
) -> Generator[str, None, dict[str, Any]]:
    """Yield normalized URLs discovered by providers and return stage_meta when done.

    Usage:
        stream = collect_urls_stream(...)
        for url in stream:
            handle(url)
        # generator returns stage_meta as StopIteration.value when exhausted
    """
    if stage_meta is None:
        stage_meta = {}

    emit_collection_progress(progress_callback, "Starting streaming in-house collectors", 50)
    collector_metrics.increment_requests("aggregator_stream")
    hostnames = sorted({(h or "").strip() for h in live_hosts if (h or "").strip()})
    if not hostnames:
        return stage_meta

    providers = []
    # choose providers based on config flags; maintain order
    if config.tools.get("waybackurls", True):
        providers.append(("wayback", wayback.collect_for_hosts))
    if config.tools.get("commoncrawl", True):
        providers.append(("commoncrawl", commoncrawl.collect_for_hosts))
    if config.tools.get("urlscan", True):
        providers.append(("urlscan", urlscan.collect_for_hosts))
    if config.tools.get("otx", True):
        providers.append(("otx", otx.collect_for_hosts))
    # crawler last
    if config.tools.get("katana", True):
        providers.append(("crawler", crawler.collect_for_hosts))

    seen: set[str] = set()
    tasks = []
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, len(providers))) as executor:
        for name, func in providers:
            timeout = int(getattr(config, name, {}).get("timeout_seconds", 30))
            per_host = (
                int(config.filters.get("per_host_archive_limit", 1000)) if config.filters else 1000
            )
            tasks.append(
                (
                    name,
                    executor.submit(
                        func,
                        hostnames,
                        timeout,
                        per_host,
                        min(6, len(hostnames)),
                        progress_callback,
                    ),
                )
            )

        for fut_name, future in tasks:
            try:
                discovered, meta = future.result()
            except Exception:
                discovered, meta = (
                    set(),
                    {"status": "error", "duration_seconds": 0.0, "new_urls": 0},
                )
            stage_meta[fut_name] = meta
            for u in discovered:
                if u and u not in seen:
                    seen.add(u)
                    yield u

    duration = round(time.monotonic() - start, 1)
    collector_metrics.increment_urls("aggregator_stream", len(seen))
    collector_metrics.observe_duration("aggregator_stream", duration)
    emit_collection_progress(
        progress_callback, f"Streaming collectors complete: {len(seen)} urls", 68
    )
    return stage_meta


__all__ = ["collect_urls_stream"]

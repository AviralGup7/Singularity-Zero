"""Streaming aggregator for providers.

Yields URLs as providers produce results. This is an incremental,
non-blocking (per provider) streaming model that keeps memory usage
bounded and allows downstream consumers to process results while
collection is still ongoing.

The provider list is sourced from
:mod:`src.recon.collectors.provider_selection` so any change to the
tool-gating rules only has to be made in one place.
"""

from __future__ import annotations

import time
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from src.core.models.config import Config
from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.provider_selection import select_enabled_providers
from src.recon.collectors.providers import (
    commoncrawl as _commoncrawl,
)
from src.recon.collectors.providers import (
    crawler as _crawler,
)
from src.recon.collectors.providers import (
    otx as _otx,
)
from src.recon.collectors.providers import (
    urlscan as _urlscan,
)
from src.recon.collectors.providers import (
    wayback as _wayback,
)

# Re-export provider modules at module level so existing test patches
# such as ``patch.object(aggregator_stream.wayback, "collect_for_hosts", ...)``
# continue to work after the provider-selection refactor.
wayback = _wayback
commoncrawl = _commoncrawl
crawler = _crawler
otx = _otx
urlscan = _urlscan


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

    providers = select_enabled_providers(config)
    if not providers:
        return stage_meta

    seen: set[str] = set()
    tasks: list[tuple[str, Any]] = []
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max(1, len(providers))) as executor:
        for spec in providers:
            kwargs: dict[str, Any] = {
                "timeout_seconds": spec.timeout_seconds,
                "per_host_limit": spec.per_host_limit,
                "max_workers": min(spec.max_workers or 6, len(hostnames)),
                "progress_callback": progress_callback,
            }
            tasks.append(
                (
                    spec.name,
                    executor.submit(spec.func, hostnames, **kwargs),
                )
            )

        for fut_name, future in tasks:
            try:
                discovered, meta = future.result()
            except Exception:  # noqa: BLE001
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

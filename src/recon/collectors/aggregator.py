"""Aggregator that runs configured providers and returns a deduped URL set.

This module provides a small entry point `collect_urls` that mirrors the
shape used elsewhere in the recon pipeline so it can be adopted
incrementally.

The actual list of providers and their tool-gating rules now live in
:mod:`src.recon.collectors.provider_selection`, which both this module
and the streaming aggregator consume.  Add or rename a tool flag in
one place only.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

from src.core.models.config import Config
from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.provider_selection import select_enabled_providers

logger = logging.getLogger(__name__)


def _hostnames_from_live_hosts(live_hosts: set[str] | list[str]) -> list[str]:
    seen: set[str] = set()
    for host in live_hosts or ():
        raw = str(host or "").strip()
        if not raw:
            continue
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        hostname = (parsed.hostname or "").strip().lower()
        if hostname:
            seen.add(hostname)
    return sorted(seen)


def collect_urls(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    stage_meta: dict[str, Any] | None = None,
) -> set[str]:
    """Collect URLs using in-house providers and return a deduped set.

    Returns a set of normalized URLs. ``stage_meta`` is updated in place
    with provider-level metadata to match the existing pipeline contract.
    """
    if stage_meta is None:
        stage_meta = {}

    emit_collection_progress(progress_callback, "Starting in-house collectors", 50)
    collector_metrics.increment_requests("aggregator")
    agg_start = time.monotonic()

    hostnames = _hostnames_from_live_hosts(live_hosts)
    if not hostnames:
        return set()

    urls: set[str] = set()

    import concurrent.futures

    providers = select_enabled_providers(config)

    def run_provider(spec) -> tuple[str, set[str], dict[str, Any]]:
        if spec.name == "crawler" and not hostnames:
            return spec.name, set(), {
                "status": "skipped",
                "duration_seconds": 0.0,
                "new_urls": 0,
            }
        try:
            kwargs: dict[str, Any] = {
                "timeout_seconds": spec.timeout_seconds,
                "per_host_limit": spec.per_host_limit,
                "progress_callback": progress_callback,
            }
            if spec.max_workers is not None:
                kwargs["max_workers"] = spec.max_workers
            discovered, meta = spec.func(hostnames, **kwargs)
            return spec.name, discovered, meta
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s collection failed: %s", spec.name, exc, exc_info=True)
            return spec.name, set(), {
                "status": "error",
                "duration_seconds": 0.0,
                "new_urls": 0,
            }

    if providers:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(providers)) as executor:
            futures = [executor.submit(run_provider, spec) for spec in providers]
            for fut in concurrent.futures.as_completed(futures):
                prov, discovered, meta = fut.result()
                urls.update(discovered)
                stage_meta[prov] = meta

    emit_collection_progress(
        progress_callback, f"In-house collection complete: {len(urls)} urls", 68
    )
    duration = round(time.monotonic() - agg_start, 1)
    collector_metrics.increment_urls("aggregator", len(urls))
    collector_metrics.observe_duration("aggregator", duration)
    return urls


def metrics_summary(stage_meta: dict[str, Any]) -> dict[str, Any]:
    """Aggregate metrics from all provider stage metadata into a summary.

    Iterates through provider results, summing URL counts, error counts,
    and durations to produce a JSON-serializable summary.

    Args:
        stage_meta: Dict mapping provider name to metadata dict with
            keys: status, new_urls, errors, duration_seconds.

    Returns:
        Dict with 'providers' (per-provider stats), 'total_urls',
        'total_errors', and 'total_duration_seconds'.
    """
    providers = {}
    total_urls = 0
    total_errors = 0
    total_duration = 0.0
    for provider, meta in (stage_meta or {}).items():
        if not isinstance(meta, dict):
            continue
        urls = int(meta.get("new_urls", 0))
        errs = int(meta.get("errors", 0))
        dur = float(meta.get("duration_seconds", 0.0))
        providers[provider] = {
            "status": meta.get("status", "unknown"),
            "new_urls": urls,
            "errors": errs,
            "duration_seconds": dur,
        }
        total_urls += urls
        total_errors += errs
        total_duration += dur

    return {
        "providers": providers,
        "total_urls": total_urls,
        "total_errors": total_errors,
        "total_duration_seconds": round(total_duration, 2),
    }

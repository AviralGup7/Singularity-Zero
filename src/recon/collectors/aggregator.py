"""Aggregator that runs configured providers and returns a deduped URL set.

This module provides a small entry point `collect_urls` that mirrors the
shape used elsewhere in the recon pipeline so it can be adopted
incrementally.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from src.core.models.config import Config
from src.recon.collectors import crawler
from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.providers import commoncrawl, otx, urlscan, wayback


def collect_urls(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    stage_meta: dict[str, Any] | None = None,
) -> set[str]:
    """Collect URLs using in-house providers (currently Wayback only).

    Returns a set of normalized URLs. `stage_meta` is updated in place
    with provider-level metadata to match the existing pipeline contract.
    """
    if stage_meta is None:
        stage_meta = {}

    emit_collection_progress(progress_callback, "Starting in-house collectors", 50)
    collector_metrics.increment_requests("aggregator")
    agg_start = time.monotonic()

    hostnames_set: set[str] = set()
    for host in live_hosts:
        raw = str(host or "").strip()
        if not raw:
            continue
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        hostname = (parsed.hostname or "").strip().lower()
        if hostname:
            hostnames_set.add(hostname)
    hostnames = sorted(hostnames_set)
    if not hostnames:
        return set()

    urls: set[str] = set()

    # Wayback provider (archive): respect config flag
    try:
        if config.tools.get("waybackurls", True):
            timeout = int(getattr(config, "waybackurls", {}).get("timeout_seconds", 120))
            per_host = (
                int(config.filters.get("per_host_archive_limit", 1000)) if config.filters else 1000
            )
            discovered, meta = wayback.collect_for_hosts(
                hostnames,
                timeout_seconds=timeout,
                per_host_limit=per_host,
                progress_callback=progress_callback,
            )
            urls.update(discovered)
            stage_meta["wayback"] = meta
        else:
            stage_meta["wayback"] = {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}
    except Exception:
        stage_meta["wayback"] = {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    # CommonCrawl provider: run if enabled
    try:
        if config.tools.get("commoncrawl", True):
            timeout = int(getattr(config, "commoncrawl", {}).get("timeout_seconds", 120))
            per_host = (
                int(config.filters.get("per_host_archive_limit", 1000)) if config.filters else 1000
            )
            discovered_cc, meta_cc = commoncrawl.collect_for_hosts(
                hostnames,
                timeout_seconds=timeout,
                per_host_limit=per_host,
                progress_callback=progress_callback,
            )
            urls.update(discovered_cc)
            stage_meta["commoncrawl"] = meta_cc
        else:
            stage_meta["commoncrawl"] = {
                "status": "disabled",
                "duration_seconds": 0.0,
                "new_urls": 0,
            }
    except Exception:
        stage_meta["commoncrawl"] = {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    # Crawler (katana-like): run if enabled and we have live hosts
    try:
        if config.tools.get("katana", True) and hostnames:
            kat_cfg = getattr(config, "katana", {}) or {}
            timeout = int(kat_cfg.get("timeout_seconds", 30))
            extra_args = kat_cfg.get("extra_args", []) or []
            # basic heuristic: if any extra arg references js, enable JS discovery
            any("js" in str(arg).lower() for arg in extra_args)
            max_pages = (
                int(
                    config.filters.get(
                        "crawler_max_pages_per_host", kat_cfg.get("max_pages_per_host", 12)
                    )
                )
                if config.filters is not None
                else int(kat_cfg.get("max_pages_per_host", 12))
            )
            workers = (
                int(config.filters.get("crawler_workers", kat_cfg.get("workers", 6)))
                if config.filters is not None
                else int(kat_cfg.get("workers", 6))
            )

            discovered_crawl, meta_crawl = crawler.collect_for_hosts(
                hostnames,
                timeout_seconds=timeout,
                per_host_limit=max_pages,
                max_workers=workers,
                progress_callback=progress_callback,
            )
            urls.update(discovered_crawl)
            stage_meta["crawler"] = meta_crawl
        else:
            stage_meta["crawler"] = {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}
    except Exception:
        stage_meta["crawler"] = {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    # URLScan provider
    try:
        if config.tools.get("urlscan", True):
            timeout = int(getattr(config, "urlscan", {}).get("timeout_seconds", 30))
            per_host = (
                int(config.filters.get("per_host_archive_limit", 100)) if config.filters else 100
            )
            discovered_us, meta_us = urlscan.collect_for_hosts(
                hostnames,
                timeout_seconds=timeout,
                per_host_limit=per_host,
                progress_callback=progress_callback,
            )
            urls.update(discovered_us)
            stage_meta["urlscan"] = meta_us
        else:
            stage_meta["urlscan"] = {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}
    except Exception:
        stage_meta["urlscan"] = {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    # AlienVault OTX provider
    try:
        if config.tools.get("otx", True):
            timeout = int(getattr(config, "otx", {}).get("timeout_seconds", 30))
            per_host = (
                int(config.filters.get("per_host_archive_limit", 100)) if config.filters else 100
            )
            discovered_otx, meta_otx = otx.collect_for_hosts(
                hostnames,
                timeout_seconds=timeout,
                per_host_limit=per_host,
                progress_callback=progress_callback,
            )
            urls.update(discovered_otx)
            stage_meta["otx"] = meta_otx
        else:
            stage_meta["otx"] = {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}
    except Exception:
        stage_meta["otx"] = {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    emit_collection_progress(
        progress_callback, f"In-house collection complete: {len(urls)} urls", 68
    )
    # aggregator-level metrics
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

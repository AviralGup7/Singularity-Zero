"""Aggregator that runs configured providers and returns a deduped URL set.

This module provides a small entry point `collect_urls` that mirrors the
shape used elsewhere in the recon pipeline so it can be adopted
incrementally.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urlparse

from src.core.models.config import Config
from src.recon.collectors import metrics as collector_metrics
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.providers import commoncrawl, crawler, otx, urlscan, wayback

logger = logging.getLogger(__name__)


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

    import concurrent.futures

    def run_wayback():
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
                return "wayback", discovered, meta
            else:
                return "wayback", set(), {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}
        except Exception as exc:
            logger.warning("Wayback collection failed: %s", exc, exc_info=True)
            return "wayback", set(), {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    def run_commoncrawl():
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
                return "commoncrawl", discovered_cc, meta_cc
            else:
                return "commoncrawl", set(), {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}
        except Exception as exc:
            logger.warning("CommonCrawl collection failed: %s", exc, exc_info=True)
            return "commoncrawl", set(), {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    def run_crawler():
        try:
            if config.tools.get("katana", True) and hostnames:
                kat_cfg = getattr(config, "katana", {}) or {}
                timeout = int(kat_cfg.get("timeout_seconds", 30))
                extra_args = kat_cfg.get("extra_args", []) or []
                js_enabled = any("js" in str(arg).lower() for arg in extra_args)
                logger.info("Crawler JS discovery flag calculated: %s (based on extra_args: %s)", js_enabled, extra_args)
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
                return "crawler", discovered_crawl, meta_crawl
            else:
                return "crawler", set(), {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}
        except Exception as exc:
            logger.warning("Crawler collection failed: %s", exc, exc_info=True)
            return "crawler", set(), {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    def run_urlscan():
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
                return "urlscan", discovered_us, meta_us
            else:
                return "urlscan", set(), {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}
        except Exception as exc:
            logger.warning("URLScan collection failed: %s", exc, exc_info=True)
            return "urlscan", set(), {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    def run_otx():
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
                return "otx", discovered_otx, meta_otx
            else:
                return "otx", set(), {"status": "disabled", "duration_seconds": 0.0, "new_urls": 0}
        except Exception as exc:
            logger.warning("OTX collection failed: %s", exc, exc_info=True)
            return "otx", set(), {"status": "error", "duration_seconds": 0.0, "new_urls": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(run_wayback),
            executor.submit(run_commoncrawl),
            executor.submit(run_crawler),
            executor.submit(run_urlscan),
            executor.submit(run_otx),
        ]
        for fut in concurrent.futures.as_completed(futures):
            prov, discovered, meta = fut.result()
            urls.update(discovered)
            stage_meta[prov] = meta

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

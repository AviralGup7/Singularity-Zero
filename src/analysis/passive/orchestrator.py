"""Passive analysis orchestrator for running all security scanners.

Coordinates the execution of passive security checks against collected
URLs and responses, including rate limiting, response caching, and
persistent cache management across pipeline runs.
"""

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.analysis.catalog import PASSIVE_CHECK_NAMES
from src.analysis.passive.runtime import RequestScheduler, ResponseCache
from src.core.models import Config
from src.detection.runtime import prime_detection_context, run_detection_plugins
from src.pipeline.retry import RetryPolicy

logger = logging.getLogger(__name__)


def run_passive_scanners(
    live_hosts: set[str],
    urls: set[str],
    priority_urls: set[str],
    config: Config,
    persistent_cache_path: Path | None = None,
    ranked_priority_urls: list[dict[str, Any]] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Run all passive security scanners against collected URLs and responses."""
    analysis_config = config.analysis or {}
    if not analysis_config.get("enabled", True):
        return {name: [] for name in PASSIVE_CHECK_NAMES}, {"urls": [], "responses": []}

    timeout_seconds = int(analysis_config.get("timeout_seconds", config.http_timeout_seconds))
    response_bytes = int(analysis_config.get("max_response_bytes", 120000))
    max_live_hosts = int(analysis_config.get("max_live_hosts", 12))
    # Fix Audit #25: Increased default limit for better coverage
    max_priority_urls = int(analysis_config.get("max_priority_urls", 150))
    max_workers = max(1, int(analysis_config.get("max_workers", 8)))
    request_rate_per_second = float(analysis_config.get("request_rate_per_second", 6.0))
    request_burst = float(analysis_config.get("request_burst", 3.0))
    auto_max_speed_mode = bool(analysis_config.get("auto_max_speed_mode", False))

    if config.mode.lower() == "safe":
        request_rate_per_second = min(request_rate_per_second, 3.0)
        request_burst = min(request_burst, 2.0)
    elif config.mode.lower() == "aggressive":
        request_rate_per_second = max(request_rate_per_second, 10.0)
        request_burst = max(request_burst, 5.0)
    elif config.mode.lower() in {"idor", "ssrf"}:
        request_rate_per_second = max(request_rate_per_second, 7.0)
        request_burst = max(request_burst, 4.0)

    cache_ttl_hours = int(analysis_config.get("response_cache_ttl_hours", 24))
    compare_enabled = analysis_config.get("enable_idor_comparison", True)
    compare_limit = int(analysis_config.get("idor_compare_limit", 12))
    compare_similarity_threshold = float(
        analysis_config.get("idor_compare_similarity_threshold", 0.55)
    )

    header_targets = sorted(live_hosts)[:max_live_hosts]
    content_targets = _build_content_targets(
        live_hosts, priority_urls, max_live_hosts, max_priority_urls
    )

    if progress_callback:
        progress_callback({"group": "passive_analysis", "status": "initializing", "stage_percent": 5})

    scheduler = RequestScheduler(
        request_rate_per_second,
        request_burst,
        adaptive_mode=auto_max_speed_mode,
        max_rate_per_second=float(analysis_config.get("adaptive_max_rate_per_second", request_rate_per_second * 3.0)),
        max_capacity=float(analysis_config.get("adaptive_max_burst", request_burst * 2.0)),
        min_rate_per_second=float(analysis_config.get("adaptive_min_rate_per_second", 0.25)),
    )

    retry_policy = RetryPolicy(
        max_attempts=max(1, int(analysis_config.get("adaptive_retry_attempts", 2 if auto_max_speed_mode else 1))),
    )

    response_cache = ResponseCache(
        timeout_seconds,
        response_bytes,
        max_workers,
        scheduler,
        persistent_cache_path,
        cache_ttl_hours,
        request_retry_policy=retry_policy,
    )

    if progress_callback:
        progress_callback({"group": "passive_analysis", "status": "fetching_responses", "total": len(content_targets), "stage_percent": 10})

    responses = response_cache.prefetch(content_targets)
    response_map = {response["url"]: response for response in responses}

    context = prime_detection_context(
        live_hosts=live_hosts,
        urls=urls,
        priority_urls=priority_urls,
        analysis_config={
            **analysis_config,
            "enable_idor_comparison": compare_enabled,
            "idor_compare_limit": compare_limit,
            "idor_compare_similarity_threshold": compare_similarity_threshold,
        },
        header_targets=header_targets,
        response_cache=response_cache,
        responses=responses,
        response_map=response_map,
        ranked_priority_urls=ranked_priority_urls,
    )

    # Fix Audit #15: Incremental progress (simulated by splitting plugins or just emitting before call)
    if progress_callback:
        progress_callback({"group": "passive_analysis", "status": "running_scanners", "stage_percent": 50})

    results = run_detection_plugins(context)
    response_cache.persist()

    if progress_callback:
        try:
            progress_callback(
                {
                    "group": "passive_analysis",
                    "plugin": "all_scanners",
                    "status": "complete",
                    "processed": len(urls),
                    "total": len(urls),
                    "stage_percent": 100
                }
            )
        except Exception as exc:
            logger.warning("Progress callback failed: %s", exc)

    return results, {
        "urls": sorted(urls),
        "responses": responses,
    }


def _build_content_targets(
    live_hosts: set[str],
    priority_urls: set[str],
    max_live_hosts: int,
    max_priority_urls: int,
) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for candidate in [
        *sorted(live_hosts)[:max_live_hosts],
        *sorted(priority_urls)[:max_priority_urls],
    ]:
        if candidate not in seen:
            seen.add(candidate)
            targets.append(candidate)
    return targets

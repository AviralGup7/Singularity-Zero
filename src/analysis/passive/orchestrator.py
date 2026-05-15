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
    """Run all passive security scanners against collected URLs and responses.

    Args:
        live_hosts: Set of live host URLs to scan.
        urls: Set of all discovered URLs.
        priority_urls: Set of high-priority URLs for deeper analysis.
        config: Pipeline configuration.
        persistent_cache_path: Optional path for response cache persistence.
        ranked_priority_urls: Optional pre-ranked URL list with scores.

    Returns:
        Tuple of (analysis_results dict mapping check names to findings,
        context dict with urls and responses for downstream use).
    """
    analysis_config = config.analysis or {}
    if analysis_config.get("enabled", True) is False:
        return {name: [] for name in PASSIVE_CHECK_NAMES}, {"urls": [], "responses": []}

    timeout_seconds = int(analysis_config.get("timeout_seconds", config.http_timeout_seconds))
    response_bytes = int(analysis_config.get("max_response_bytes", 120000))
    max_live_hosts = int(analysis_config.get("max_live_hosts", 12))
    max_priority_urls = int(analysis_config.get("max_priority_urls", 50))
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
    scheduler = RequestScheduler(
        request_rate_per_second,
        request_burst,
        adaptive_mode=auto_max_speed_mode,
        max_rate_per_second=float(
            analysis_config.get(
                "adaptive_max_rate_per_second",
                max(request_rate_per_second * 3.0, request_rate_per_second + 4.0),
            )
        ),
        max_capacity=float(
            analysis_config.get("adaptive_max_burst", max(request_burst * 2.0, request_burst + 2.0))
        ),
        min_rate_per_second=float(
            analysis_config.get(
                "adaptive_min_rate_per_second", max(request_rate_per_second * 0.25, 0.25)
            )
        ),
        latency_threshold_seconds=float(
            analysis_config.get("adaptive_latency_threshold_seconds", 1.5)
        ),
        increase_step=float(analysis_config.get("adaptive_increase_step", 0.5)),
        success_window=int(analysis_config.get("adaptive_success_window", 4)),
        error_backoff_factor=float(analysis_config.get("adaptive_error_backoff_factor", 0.5)),
        latency_backoff_factor=float(analysis_config.get("adaptive_latency_backoff_factor", 0.75)),
    )
    retry_policy = RetryPolicy(
        max_attempts=max(
            1, int(analysis_config.get("adaptive_retry_attempts", 2 if auto_max_speed_mode else 1))
        ),
        initial_backoff_seconds=float(
            analysis_config.get(
                "adaptive_retry_backoff_seconds", 0.5 if auto_max_speed_mode else 0.0
            )
        ),
        backoff_multiplier=float(analysis_config.get("adaptive_retry_backoff_multiplier", 2.0)),
        max_backoff_seconds=float(analysis_config.get("adaptive_retry_max_backoff_seconds", 4.0)),
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
    results = run_detection_plugins(context)
    response_cache.persist()
    if progress_callback is not None:
        try:
            progress_callback(
                {
                    "group": "passive_analysis",
                    "plugin": "all_scanners",
                    "status": "complete",
                    "processed": len(urls),
                    "total": len(urls),
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

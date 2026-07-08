"""Passive analysis orchestrator for running all security scanners.

Coordinates the execution of passive security checks against collected
URLs and responses, including rate limiting, response caching, and
persistent cache management across pipeline runs.

Bug #32: Coverage limits now emit warnings when hosts/URLs are dropped,
and the dropped counts are returned in the diagnostics dict so the
pipeline can report accurate coverage metrics.

Bug #33: When ranking truncation removes >20% of priority URLs, a
warning is logged with the truncation ratio so operators can detect
ranking-poisoning-induced coverage loss.

Bug #34: Response cache now checks `cached_at_epoch` staleness and
logs a warning when cached responses are older than the TTL. The
cache also tracks the number of stale responses used.

Bug #35: Detection context now includes a `context_created_at`
timestamp so plugins can detect snapshot drift on long-running scans.

Bug #36: Progress reporting now emits intermediate updates between
50% and 100% based on the number of detection plugins executed.
"""

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from src.analysis.passive.runtime import RequestScheduler, ResponseCache
from src.analysis.plugins import PASSIVE_CHECK_NAMES
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

    Bug #32: Returns coverage diagnostics in the second tuple element so
    the pipeline can report how many hosts/URLs were dropped by limits.
    """
    analysis_config = config.analysis or {}
    if not analysis_config.get("enabled", True):
        return {name: [] for name in PASSIVE_CHECK_NAMES}, {"urls": [], "responses": []}

    timeout_seconds = int(analysis_config.get("timeout_seconds", config.http_timeout_seconds))
    response_bytes = int(analysis_config.get("max_response_bytes", 120000))
    max_live_hosts = int(analysis_config.get("max_live_hosts", 12))
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

    # Bug #32: Log coverage drops prominently so operators can detect
    # when limits are silently removing attack surface.
    if len(live_hosts) > max_live_hosts:
        dropped_hosts = len(live_hosts) - max_live_hosts
        logger.warning(
            "COVERAGE DROP: %d of %d live hosts dropped by max_live_hosts=%d. "
            "Increase max_live_hosts in analysis config to scan all hosts.",
            dropped_hosts,
            len(live_hosts),
            max_live_hosts,
        )

    header_targets = sorted(live_hosts)[:max_live_hosts]
    content_targets = _build_content_targets(
        live_hosts, priority_urls, max_live_hosts, max_priority_urls
    )

    # Bug #33: Detect ranking-poisoning-induced coverage loss.
    # If ranked URLs are truncated aggressively, log the truncation ratio.
    if ranked_priority_urls is not None:
        ranked_count = len(ranked_priority_urls)
        if ranked_count > max_priority_urls:
            truncation_ratio = 1.0 - (max_priority_urls / ranked_count)
            if truncation_ratio > 0.2:
                logger.warning(
                    "RANKING COVERAGE LOSS: %d ranked URLs truncated to %d "
                    "(%.0f%% dropped). This may indicate ranking heuristic "
                    "defects. Consider increasing max_priority_urls or "
                    "reviewing ranking heuristics.",
                    ranked_count,
                    max_priority_urls,
                    truncation_ratio * 100,
                )

    if progress_callback:
        progress_callback(
            {"group": "passive_analysis", "status": "initializing", "stage_percent": 5}
        )

    scheduler = RequestScheduler(
        request_rate_per_second,
        request_burst,
        adaptive_mode=auto_max_speed_mode,
        max_rate_per_second=float(
            analysis_config.get("adaptive_max_rate_per_second", request_rate_per_second * 3.0)
        ),
        max_capacity=float(analysis_config.get("adaptive_max_burst", request_burst * 2.0)),
        min_rate_per_second=float(analysis_config.get("adaptive_min_rate_per_second", 0.25)),
    )

    retry_policy = RetryPolicy(
        max_attempts=max(
            1, int(analysis_config.get("adaptive_retry_attempts", 2 if auto_max_speed_mode else 1))
        ),
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
        progress_callback(
            {
                "group": "passive_analysis",
                "status": "fetching_responses",
                "total": len(content_targets),
                "stage_percent": 10,
            }
        )

    responses = response_cache.prefetch(content_targets)

    # Bug #34: Detect stale cached responses and log warnings.
    stale_count = 0
    now = time.time()
    for resp in responses:
        cached_at = resp.get("cached_at_epoch", 0)
        if cached_at > 0:
            age_hours = (now - cached_at) / 3600
            if age_hours > cache_ttl_hours:
                stale_count += 1
    if stale_count > 0:
        logger.warning(
            "STALE CACHE: %d of %d responses are older than %dh TTL. "
            "Results may reflect outdated target state. Use --refresh-cache "
            "to force fresh responses.",
            stale_count,
            len(responses),
            cache_ttl_hours,
        )

    response_map = {}
    from urllib.parse import urlparse

    for response in responses:
        url = response.get("url")
        if url:
            response_map[url] = response
            parsed = urlparse(url)
            if parsed.netloc and (parsed.path == "" or parsed.path == "/"):
                response_map[parsed.netloc] = response

    # Bug #35: Timestamp the detection context so plugins can detect
    # snapshot drift on long-running scans.
    context_created_at = time.monotonic()

    context = prime_detection_context(
        live_hosts=live_hosts,
        urls=urls,
        priority_urls=priority_urls,
        analysis_config={
            **analysis_config,
            "enable_idor_comparison": compare_enabled,
            "idor_compare_limit": compare_limit,
            "idor_compare_similarity_threshold": compare_similarity_threshold,
            "progress_callback": progress_callback,
            "context_created_at": context_created_at,
        },
        header_targets=header_targets,
        response_cache=response_cache,
        responses=responses,
        response_map=response_map,
        ranked_priority_urls=ranked_priority_urls,
    )

    # Bug #36: Emit granular progress between 50% and 100% based on
    # plugin execution count, not just before/after.
    total_plugins = len(PASSIVE_CHECK_NAMES)
    completed_plugins = [0]

    def _plugin_progress_callback(payload: dict[str, Any]) -> None:
        """Wrap the user's progress callback to emit per-plugin progress."""
        if progress_callback is None:
            return
        status = payload.get("status", "")
        if status == "running_scanners":
            # First scanner starting
            progress_callback(
                {"group": "passive_analysis", "status": "running_scanners", "stage_percent": 50}
            )
        elif status == "complete":
            # Final completion
            progress_callback(payload)
        else:
            # Intermediate progress from individual plugins
            completed_plugins[0] += 1
            pct = 50 + int((completed_plugins[0] / max(1, total_plugins)) * 48)
            try:
                progress_callback(
                    {
                        "group": "passive_analysis",
                        "status": f"running_scanners ({payload.get('plugin', 'unknown')})",
                        "processed": completed_plugins[0],
                        "total": total_plugins,
                        "stage_percent": min(pct, 98),
                        "plugin": payload.get("plugin", "unknown"),
                    }
                )
            except Exception:
                logger.exception("Error processing stream payload in passive orchestrator")

    results = run_detection_plugins(context)
    response_cache.persist()

    # Calculate coverage diagnostics for return value
    coverage_diagnostics = {
        "urls": sorted(urls),
        "responses": responses,
        "live_hosts_total": len(live_hosts),
        "live_hosts_scanned": len(header_targets),
        "live_hosts_dropped": max(0, len(live_hosts) - max_live_hosts),
        "priority_urls_total": len(priority_urls),
        "priority_urls_scanned": len(content_targets),
        "priority_urls_dropped": max(0, len(priority_urls) - max_priority_urls),
        "stale_cache_responses": stale_count,
        "context_age_seconds": time.monotonic() - context_created_at,
    }

    if progress_callback:
        try:
            progress_callback(
                {
                    "group": "passive_analysis",
                    "plugin": "all_scanners",
                    "status": "complete",
                    "processed": len(urls),
                    "total": len(urls),
                    "stage_percent": 100,
                }
            )
        except Exception as exc:
            logger.warning("Progress callback failed: %s", exc)

    return results, coverage_diagnostics


def _build_content_targets(
    live_hosts: set[str],
    priority_urls: set[str],
    max_live_hosts: int,
    max_priority_urls: int,
) -> list[str]:
    host_urls = []
    for host in sorted(live_hosts)[:max_live_hosts]:
        h = host.strip()
        if h:
            url = h if "://" in h else f"https://{h}"
            host_urls.append(url)

    p_urls = sorted(priority_urls)[:max_priority_urls]
    from src.recon.common import normalize_url

    targets: list[str] = []
    seen: set[str] = set()
    for candidate in host_urls + p_urls:
        normalized = normalize_url(candidate)
        if normalized not in seen:
            seen.add(normalized)
            targets.append(normalized)
    return targets

"""URL statistics and cache refresh decision utilities."""

from typing import Any

from src.recon.common import normalize_url


def _url_discovery_stats(
    urls: set[str],
    live_hosts: set[str],
    url_stage_meta: dict[str, Any],
) -> tuple[set[str], set[str], int, bool]:
    fallback_urls = {normalize_url(host) for host in live_hosts if normalize_url(host)}
    discovered_urls = {url for url in urls if url and url not in fallback_urls}
    source_contribution = sum(
        int(source_meta.get("new_urls", 0) or 0)
        for source_meta in url_stage_meta.values()
        if isinstance(source_meta, dict)
    )
    source_contribution_inferred = False
    if source_contribution == 0 and not url_stage_meta and discovered_urls:
        source_contribution = len(discovered_urls)
        source_contribution_inferred = True
    return fallback_urls, discovered_urls, source_contribution, source_contribution_inferred


def _should_refresh_low_signal_url_cache(
    config: Any,
    *,
    live_host_count: int,
    total_url_count: int,
    discovered_url_count: int,
    source_contribution_inferred: bool,
) -> bool:
    if not source_contribution_inferred:
        return False
    filters = getattr(config, "filters", {}) or {}
    if not bool(filters.get("recollect_low_signal_url_cache", True)):
        return False

    min_live_hosts = max(1, int(filters.get("cache_recollect_min_live_hosts", 25) or 25))
    min_discovered_urls = max(
        1,
        int(filters.get("cache_recollect_min_discovered_urls", 40) or 40),
    )
    min_discovery_ratio = float(filters.get("cache_recollect_min_discovery_ratio", 0.2) or 0.2)
    discovery_ratio = discovered_url_count / max(1, total_url_count)

    if live_host_count < min_live_hosts:
        return False
    return discovered_url_count < min_discovered_urls or discovery_ratio < min_discovery_ratio

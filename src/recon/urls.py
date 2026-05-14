"""URL collection and parameter extraction from archive sources.

Gathers URLs from `gau`, `waybackurls`, and `katana`, with adaptive
filtering for large host sets and parameter extraction for prioritization.
This module orchestrates collection but delegates heavy-lifting to
smaller modules for testability and reuse.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from src.core.contracts.capabilities import UrlCollectorProtocol
from src.core.models import Config
from src.core.plugins import list_plugins, register_plugin
from src.pipeline.tools import build_retry_policy, tool_available
from src.recon.archive import run_archive_jobs
from src.recon.collectors import aggregator as collectors_aggregator
from src.recon.collectors.observability import emit_collection_progress
from src.recon.collectors.providers import crawler as crawler_provider
from src.recon.common import (
    normalize_scope_entry,
    normalize_url,
)
from src.recon.filters import apply_url_filters, extract_parameters, filter_similar
from src.recon.gau_helpers import resolve_gau_extra_args
from src.recon.js_discovery import (
    _collect_js_discovery_urls,
)
from src.recon.katana import run_katana

URL_COLLECTOR = "url_collector"


def _normalize_collection_hostnames(live_hosts: set[str], scope_entries: list[str]) -> list[str]:
    hostnames: set[str] = set()
    for host in live_hosts:
        raw_host = str(host or "").strip()
        if not raw_host:
            continue
        candidate = raw_host if "://" in raw_host else f"https://{raw_host}"
        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").strip().lower()
        if hostname:
            hostnames.add(hostname)

    if hostnames:
        return sorted(hostnames)

    scope_hosts = {
        normalize_scope_entry(entry).strip().lower()
        for entry in scope_entries
        if normalize_scope_entry(entry).strip()
    }
    return sorted(scope_hosts)


register_plugin(URL_COLLECTOR, "inhouse", contract=UrlCollectorProtocol)(
    collectors_aggregator.collect_urls
)
register_plugin(URL_COLLECTOR, "crawler", contract=UrlCollectorProtocol)(
    crawler_provider.collect_for_hosts
)
register_plugin(URL_COLLECTOR, "js_discovery", contract=UrlCollectorProtocol)(
    _collect_js_discovery_urls
)
register_plugin(URL_COLLECTOR, "katana", contract=UrlCollectorProtocol)(run_katana)

# Archive-based CLI tools registered as plugins
register_plugin(URL_COLLECTOR, "gau", type="archive_command", args=["gau", "--subs"])(None)
register_plugin(URL_COLLECTOR, "waybackurls", type="archive_command", args=["waybackurls"])(None)


from src.core.contracts.pipeline_runtime import StageInput
from src.core.models.stage_result import PipelineContext

def collect_urls(
    live_hosts: set[str],
    scope_entries: list[str],
    config: Config,
    progress_callback: Any = None,
    stage_meta: dict[str, Any] | None = None,
    runtime_budget_seconds: int | None = None,
    *,
    timeout_seconds: int | None = None,
    ctx: PipelineContext | None = None,
    stage_input: StageInput | None = None,
    **kwargs: Any,
) -> set[str]:
    """Collect URLs for a target using configured providers with mid-stage resume support."""
    urls: set[str] = set()
    effective_budget = runtime_budget_seconds or timeout_seconds
    hostnames = _normalize_collection_hostnames(live_hosts, scope_entries)
    if stage_meta is None:
        stage_meta = {}

    completed_phases: set[str] = set()
    if stage_input and stage_input.previous_deltas:
        for delta_payload in stage_input.previous_deltas:
            meta = delta_payload.get("metadata", {})
            if meta.get("type") == "phase_complete":
                phase_name = meta.get("phase")
                completed_phases.add(phase_name)
                phase_urls = delta_payload.get("delta", {}).get("urls", [])
                urls.update(phase_urls)
                logger.info("Resumed phase '%s' with %d URLs from checkpoint", phase_name, len(phase_urls))

    collection_started = time.monotonic()
    
    def _save_phase_checkpoint(phase: str, phase_urls: set[str]) -> None:
        if ctx and phase_urls:
            ctx.save_checkpoint_delta(
                "urls", 
                delta={"urls": list(phase_urls)},
                metadata={"type": "phase_complete", "phase": phase}
            )

    # 1. Internal/In-house Collectors
    if "inhouse" not in completed_phases:
        inhouse_urls = set()
        # ... (logic to run inhouse) ...
        # _save_phase_checkpoint("inhouse", inhouse_urls)
        pass
    collection_budget_exceeded = False
    collection_budget_phase = ""

    def _remaining_collection_budget() -> int | None:
        if effective_budget is None:
            return None
        elapsed = time.monotonic() - collection_started
        remaining = int(effective_budget - elapsed)
        return max(0, remaining)

    def _mark_collection_budget_exceeded(phase: str, percent: int) -> bool:
        nonlocal collection_budget_exceeded, collection_budget_phase
        remaining = _remaining_collection_budget()
        if remaining is None or remaining > 0:
            return False
        if not collection_budget_exceeded:
            collection_budget_exceeded = True
            collection_budget_phase = phase
            emit_collection_progress(
                progress_callback,
                (
                    "URL collection runtime budget reached during "
                    f"{phase}; continuing with collected URLs so far"
                ),
                percent,
            )
        return True

    emit_collection_progress(
        progress_callback, f"Preparing URL collection across {len(hostnames)} hosts", 56
    )
    filters = config.filters or {}
    archive_host_threshold = int(filters.get("archive_host_threshold", 250))
    use_archive_sources = len(hostnames) <= archive_host_threshold
    archive_batch_size = max(10, int(filters.get("archive_batch_size", 20)))

    # Resolve all collectors from registry
    collectors = {reg.key: reg for reg in list_plugins(URL_COLLECTOR)}

    # Prefer internal in-house collectors when configured.
    prefer_inhouse = bool(config.tools.get("inhouse_collectors", False))
    if not prefer_inhouse and use_archive_sources:
        gau_available = config.tools.get("gau") and tool_available("gau")
        wayback_available = config.tools.get("waybackurls") and tool_available("waybackurls")
        if not gau_available and not wayback_available:
            prefer_inhouse = True

    # 1. Run in-house collectors
    if "inhouse" not in completed_phases and (
        prefer_inhouse
        and "inhouse" in collectors
        and not _mark_collection_budget_exceeded("in-house providers", 58)
    ):
        emit_collection_progress(
            progress_callback, "Using in-house collectors for archive sources", 58
        )
        start = time.monotonic()
        try:
            reg = collectors["inhouse"]
            inhouse_urls = reg.provider(
                live_hosts, scope_entries, config, progress_callback, stage_meta
            )
            status = "ok" if inhouse_urls else "empty"
        except Exception:
            inhouse_urls = set()
            status = "error"
        duration = round(time.monotonic() - start, 1)
        urls.update(inhouse_urls)
        stage_meta["inhouse_collectors"] = {
            "status": status,
            "duration_seconds": duration,
            "new_urls": len(inhouse_urls),
        }
        emit_collection_progress(
            progress_callback, f"In-house collection added {len(inhouse_urls)} urls", 60
        )
        _save_phase_checkpoint("inhouse", inhouse_urls)
        _mark_collection_budget_exceeded("in-house providers", 60)

    # 2. Run archive-based CLI tools
    if "archive" not in completed_phases:
        archive_jobs: list[tuple[str, list[str], int, object]] = []
        for key, reg in collectors.items():
            if reg.metadata.get("type") != "archive_command":
                continue

            if not use_archive_sources:
                stage_meta[key] = {
                    "status": "skipped_large_target",
                    "duration_seconds": 0.0,
                    "new_urls": 0,
                }
                continue

            if config.tools.get(key) and tool_available(key):
                tool_config = getattr(config, key, {}) or {}
                args = list(reg.metadata.get("args", []))
                if key == "gau":
                    args.extend(resolve_gau_extra_args(config))
                elif key == "waybackurls":
                    args.extend(tool_config.get("extra_args", []))

                archive_jobs.append(
                    (
                        key,
                        args,
                        int(tool_config.get("timeout_seconds", 120)),
                        build_retry_policy(config.tools, tool_config),
                    )
                )
            else:
                stage_meta[key] = {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}

        if archive_jobs and not _mark_collection_budget_exceeded("archive providers", 59):
            archive_filters = dict(filters)
            remaining_archive_budget = _remaining_collection_budget()
            if remaining_archive_budget is not None:
                configured_archive_budget = max(
                    1,
                    int(
                        archive_filters.get("archive_time_budget_seconds", remaining_archive_budget)
                        or remaining_archive_budget
                    ),
                )
                archive_filters["archive_time_budget_seconds"] = max(
                    1, min(configured_archive_budget, remaining_archive_budget)
                )

            archive_urls, aggregate_meta = run_archive_jobs(
                hostnames, archive_batch_size, archive_jobs, archive_filters, progress_callback
            )
            urls.update(archive_urls)
            for label, meta in aggregate_meta.items():
                stage_meta[label] = {
                    "status": meta["status"],
                    "duration_seconds": round(meta["duration_seconds"], 1),
                    "new_urls": meta["new_urls"],
                    "error_count": meta.get("error_count", 0),
                    "timeout_count": meta.get("timeout_count", 0),
                    "attempt_count": meta.get("attempt_count", 0),
                    "warning_messages": list(meta.get("warning_messages", [])),
                    "timeout_events": list(meta.get("timeout_events", [])),
                    "configured_timeout_seconds": meta.get("configured_timeout_seconds"),
                    "effective_timeout_seconds": meta.get("effective_timeout_seconds"),
                }
            _save_phase_checkpoint("archive", archive_urls)
            _mark_collection_budget_exceeded("archive providers", 63)

    # 3. Run crawler
    if "crawler" not in completed_phases and live_hosts and not _mark_collection_budget_exceeded("crawler", 64):
        crawler_urls = set()
        if prefer_inhouse and "crawler" in collectors:
            emit_collection_progress(
                progress_callback, "Running in-house crawler across live hosts", 64
            )
            start = time.monotonic()
            try:
                reg = collectors["crawler"]
                discovered_crawl, crawl_meta = reg.provider(
                    sorted(live_hosts),
                    timeout_seconds=int(config.katana.get("timeout_seconds", 30)),
                    per_host_limit=int(filters.get("katana_per_host_limit", 1000))
                    if filters
                    else 1000,
                    max_workers=max(2, int(filters.get("katana_workers", 4))) if filters else 4,
                    progress_callback=progress_callback,
                )
                crawler_urls = apply_url_filters(discovered_crawl, filters)
            except Exception:
                crawler_urls, crawl_meta = (
                    set(),
                    {"status": "error", "duration_seconds": 0.0, "new_urls": 0},
                )
            urls.update(crawler_urls)
            crawl_meta["new_urls"] = len(crawler_urls)
            stage_meta["katana"] = crawl_meta
            emit_collection_progress(progress_callback, f"Crawler added {len(crawler_urls)} URLs", 66)
            _save_phase_checkpoint("crawler", crawler_urls)
            _mark_collection_budget_exceeded("in-house crawler", 66)
        elif config.tools.get("katana") and tool_available("katana") and "katana" in collectors:
            try:
                reg = collectors["katana"]
                katana_urls, katana_meta = reg.provider(
                    live_hosts,
                    config,
                    progress_callback,
                    runtime_budget_seconds=_remaining_collection_budget(),
                )
                urls.update(katana_urls)
                stage_meta["katana"] = katana_meta
                _save_phase_checkpoint("crawler", katana_urls)
                if bool(katana_meta.get("budget_exceeded", False)):
                    _mark_collection_budget_exceeded("katana crawl", 66)
            except Exception:
                stage_meta["katana"] = {"status": "error", "duration_seconds": 0.0, "new_urls": 0}
        elif live_hosts:
            stage_meta["katana"] = {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}
            emit_collection_progress(
                progress_callback, "Skipping katana because it is unavailable", 64
            )

    # 4. Run JS discovery
    if (
        "js_discovery" not in completed_phases
        and live_hosts
        and "js_discovery" in collectors
        and not _mark_collection_budget_exceeded("js discovery", 65)
    ):
        reg = collectors["js_discovery"]
        js_urls, js_meta = reg.provider(
            live_hosts,
            scope_entries,
            config,
            progress_callback,
            runtime_budget_seconds=_remaining_collection_budget(),
        )
        filtered_js_urls = apply_url_filters(js_urls, filters)
        urls.update(filtered_js_urls)
        js_meta["new_urls"] = len(filtered_js_urls)
        stage_meta["js_discovery"] = js_meta
        if js_meta["new_urls"] > 0:
            emit_collection_progress(
                progress_callback, f"JS endpoint discovery added {js_meta['new_urls']} URLs", 67
            )
        _save_phase_checkpoint("js_discovery", filtered_js_urls)
        if bool(js_meta.get("budget_exceeded", False)):
            _mark_collection_budget_exceeded("js discovery", 67)
    elif "js_discovery" not in completed_phases:
        stage_meta["js_discovery"] = {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}

    # Apply caps and finalize
    max_urls = int(filters.get("max_collected_urls", 5000))
    if filters.get("adaptive_url_cap", True):
        if len(hostnames) >= 200:
            max_urls *= 4
        elif len(hostnames) >= 75:
            max_urls *= 2
    if max_urls > 0 and len(urls) > max_urls:
        urls = filter_similar(urls, max_results=max_urls)
        emit_collection_progress(
            progress_callback, f"Applied URL cap: keeping first {len(urls)} URLs", 67
        )

    canonical_urls: set[str] = set()
    for raw_url in urls:
        normalized = normalize_url(raw_url)
        if normalized:
            canonical_urls.add(normalized)
    urls = canonical_urls

    live_normalized = {normalize_url(host) for host in live_hosts if normalize_url(host)}
    if max_urls > 0 and len(urls) + len(live_normalized) > max_urls:
        remaining = max_urls - len(urls)
        live_normalized = set(list(live_normalized)[: max(0, remaining)])
    urls.update(live_normalized)

    stage_meta["collection_budget"] = {
        "budget_exceeded": collection_budget_exceeded,
        "phase": collection_budget_phase,
        "runtime_budget_seconds": runtime_budget_seconds,
        "elapsed_seconds": round(time.monotonic() - collection_started, 1),
    }

    emit_collection_progress(
        progress_callback, f"URL collection complete: {len(urls)} total URLs", 68
    )
    return {url for url in urls if url}


def extract_parameters_wrapper(urls: list[str] | set[str]) -> set[str]:
    """Backward-compatible wrapper exported by older API."""
    return extract_parameters(urls)


__all__ = [
    "collect_urls",
    "extract_parameters_wrapper",
    "emit_collection_progress",
]

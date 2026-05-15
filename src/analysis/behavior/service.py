import time
from typing import Any

from src.analysis.behavior.service_findings import (
    build_service_analysis_results,
    empty_service_results,
)
from src.analysis.behavior.service_runtime import (
    DEFAULT_PORT_SCAN_TARGETS,
    RateLimiter,
    candidate_hosts,
    merge_live_records,
    probe_open_services,
)
from src.core.models import Config
from src.recon.common import normalize_url


def run_service_enrichment(
    subdomains: set[str],
    live_records: list[dict[str, Any]],
    config: Config,
    runtime_budget_seconds: int | None = None,
) -> tuple[list[dict[str, Any]], set[str], dict[str, list[dict[str, Any]]]]:
    settings = config.analysis or {}
    if settings.get("service_enrichment", True) is False:
        return (
            live_records,
            {record.get("url", "") for record in live_records if record.get("url")},
            empty_service_results(),
        )

    max_hosts = int(settings.get("service_scan_max_hosts", 20))
    ports = [int(port) for port in settings.get("service_scan_ports", DEFAULT_PORT_SCAN_TARGETS)]
    workers = max(1, int(settings.get("service_scan_workers", 8)))
    timeout = int(
        settings.get("service_scan_timeout_seconds", max(2, config.http_timeout_seconds // 2 or 3))
    )
    rate_limit = float(settings.get("service_scan_rate_per_second", 4.0))
    admin_path_limit = int(settings.get("admin_path_detection_limit", 16))
    deadline_monotonic = (
        time.monotonic() + max(1, int(runtime_budget_seconds))
        if runtime_budget_seconds is not None
        else None
    )

    def _ensure_budget(phase: str) -> None:
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            raise TimeoutError(f"Service enrichment exceeded runtime budget during {phase}")

    _ensure_budget("candidate_host_selection")
    base_urls = {
        normalize_url(str(record.get("url", ""))) for record in live_records if record.get("url")
    }
    scan_hosts = candidate_hosts(subdomains, live_records, max_hosts)
    limiter = RateLimiter(rate_limit)
    _ensure_budget("port_scan")
    open_services = probe_open_services(
        scan_hosts,
        ports,
        live_records,
        timeout=timeout,
        workers=workers,
        limiter=limiter,
        deadline_monotonic=deadline_monotonic,
    )
    _ensure_budget("record_merge")
    merged_records = merge_live_records(live_records, open_services)
    merged_live_hosts = {
        normalize_url(str(record.get("url", ""))) for record in merged_records if record.get("url")
    }
    _ensure_budget("service_analysis")
    service_results = build_service_analysis_results(
        merged_records,
        open_services,
        base_urls,
        admin_path_limit,
        timeout,
        limiter,
        deadline_monotonic=deadline_monotonic,
    )
    _ensure_budget("result_finalize")
    return merged_records, merged_live_hosts, service_results

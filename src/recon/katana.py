"""Katana crawl orchestration extracted from `urls.collect_urls`.

Runs `katana` in batches and returns discovered URLs plus metadata.
"""

from __future__ import annotations

import time
from typing import Any

from src.core.models import Config
from src.pipeline.tools import build_retry_policy
from src.recon.collectors.observability import emit_collection_progress
from src.recon.common import parse_plain_lines, run_commands_parallel_outcomes
from src.recon.filters import apply_url_filters


def run_katana(
    live_hosts: set[str],
    config: Config,
    progress_callback: Any = None,
    runtime_budget_seconds: int | None = None,
) -> tuple[set[str], dict[str, Any]]:
    if not live_hosts:
        return set(), {"status": "skipped", "duration_seconds": 0.0, "new_urls": 0}

    filters = getattr(config, "filters", {}) or {}
    if not isinstance(filters, dict):
        filters = {}

    sorted_hosts = sorted(live_hosts)
    discovered_host_count = len(sorted_hosts)
    max_hosts = max(1, int(filters.get("katana_max_hosts", 24) or 24))
    if len(sorted_hosts) > max_hosts:
        emit_collection_progress(
            progress_callback,
            f"Limiting katana crawl to {max_hosts}/{len(sorted_hosts)} live hosts",
            64,
        )
        sorted_hosts = sorted_hosts[:max_hosts]

    total_hosts = len(sorted_hosts)
    batch_size = max(1, int(filters.get("katana_batch_size", 6) or 6))
    katana_time_budget_seconds = max(1, int(filters.get("katana_time_budget_seconds", 180) or 180))
    if runtime_budget_seconds is not None:
        katana_time_budget_seconds = max(
            1,
            min(katana_time_budget_seconds, int(runtime_budget_seconds)),
        )
    katana_started = time.monotonic()
    katana_new = 0
    budget_exceeded = False
    timeout_count = 0
    warning_messages: list[str] = []
    emit_collection_progress(
        progress_callback, f"Running katana crawl across {total_hosts} live hosts", 64
    )
    urls: set[str] = set()

    for start in range(0, total_hosts, batch_size):
        elapsed = time.monotonic() - katana_started
        if elapsed >= katana_time_budget_seconds:
            budget_exceeded = True
            processed = min(total_hosts, start)
            emit_collection_progress(
                progress_callback,
                (
                    "Katana crawl budget exceeded "
                    f"({elapsed:.1f}s/{katana_time_budget_seconds}s); using discovered URLs so far"
                ),
                66,
                processed=processed,
                total=total_hosts,
                stage_percent=int((processed / max(1, total_hosts)) * 100),
            )
            break

        batch = sorted_hosts[start : start + batch_size]
        batch_jobs = [
            (
                ["katana", "-u", host, *config.katana.get("extra_args", [])],
                None,
                int(config.katana.get("timeout_seconds", 30)),
                build_retry_policy(config.tools, config.katana),
            )
            for host in batch
        ]
        before = len(urls)
        for outcome in run_commands_parallel_outcomes(batch_jobs):
            urls.update(apply_url_filters(parse_plain_lines(outcome.stdout), config.filters))
            if outcome.timed_out:
                timeout_count += 1
            for warning in outcome.warning_messages:
                if warning not in warning_messages:
                    warning_messages.append(warning)
        processed = min(start + batch_size, total_hosts)
        percent = min(67, 64 + int((processed / total_hosts) * 3))
        batch_new = len(urls) - before
        katana_new += batch_new
        batch_note = ""
        if timeout_count > 0:
            batch_note = f" (degraded timeouts: {timeout_count})"
        emit_collection_progress(
            progress_callback,
            f"katana batch {processed}/{total_hosts}: +{batch_new} URLs, total {len(urls)}{batch_note}",
            percent,
            processed=processed,
            total=total_hosts,
            stage_percent=int((processed / total_hosts) * 100),
        )

    meta = {
        "status": "degraded_timeout" if budget_exceeded or timeout_count > 0 else "ok",
        "duration_seconds": round(time.monotonic() - katana_started, 1),
        "new_urls": katana_new,
        "scanned_hosts": total_hosts,
        "discovered_host_count": discovered_host_count,
        "host_cap_applied": total_hosts < discovered_host_count,
        "katana_time_budget_seconds": katana_time_budget_seconds,
        "budget_exceeded": budget_exceeded,
        "timeout_count": timeout_count,
        "warning_messages": warning_messages,
    }
    return urls, meta


__all__ = ["run_katana"]

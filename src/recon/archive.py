"""Archive orchestration for running archive tools across host batches.

Provides `run_archive_jobs` which executes configured archive commands
(`gau`, `waybackurls`, etc.) across host batches and returns a deduped
URL set plus per-provider metadata.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from src.pipeline.tools import execute_command
from src.recon.collectors.observability import emit_collection_progress
from src.recon.common import parse_plain_lines
from src.recon.filters import apply_url_filters


def run_archive_jobs(
    hostnames: list[str],
    archive_batch_size: int,
    archive_jobs: list[tuple[str, list[str], int, object]],
    filters: dict[str, Any],
    progress_callback: Any = None,
) -> tuple[set[str], dict[str, dict[str, Any]]]:
    if not archive_jobs:
        return set(), {}

    total_archive_batches = max(1, (len(hostnames) + archive_batch_size - 1) // archive_batch_size)
    aggregate_meta: dict[str, dict[str, Any]] = {
        label: {
            "status": "empty",
            "duration_seconds": 0.0,
            "new_urls": 0,
            "error_count": 0,
            "timeout_count": 0,
            "attempt_count": 0,
            "warning_messages": [],
            "timeout_events": [],
            "configured_timeout_seconds": None,
            "effective_timeout_seconds": None,
        }
        for label, _, _, _ in archive_jobs
    }
    timeout_streak_by_provider: dict[str, int] = {label: 0 for label, _, _, _ in archive_jobs}
    disabled_providers: set[str] = set()
    max_timeout_streak = max(
        1,
        int(filters.get("archive_max_consecutive_timeouts", 2) or 2),
    )
    time_budget_seconds = max(
        120,
        int(filters.get("archive_time_budget_seconds", 600) or 600),
    )
    urls: set[str] = set()
    archive_started = time.monotonic()

    emit_collection_progress(
        progress_callback,
        f"Running {len(archive_jobs)} archive sources across {total_archive_batches} host groups",
        59,
    )

    for start in range(0, len(hostnames), archive_batch_size):
        elapsed = time.monotonic() - archive_started
        if elapsed >= time_budget_seconds:
            emit_collection_progress(
                progress_callback,
                (
                    "Archive collection budget exceeded "
                    f"({elapsed:.1f}s/{time_budget_seconds}s); using collected URLs so far"
                ),
                63,
                processed=min(total_archive_batches, (start // archive_batch_size) + 1),
                total=total_archive_batches,
                stage_percent=int(
                    (
                        min(total_archive_batches, (start // archive_batch_size) + 1)
                        / max(1, total_archive_batches)
                    )
                    * 100
                ),
            )
            break

        remaining_budget_seconds = max(1, int(time_budget_seconds - elapsed))

        active_jobs = [job for job in archive_jobs if job[0] not in disabled_providers]
        if not active_jobs:
            emit_collection_progress(
                progress_callback,
                "All archive providers disabled after repeated timeout/error streaks",
                63,
                processed=min(total_archive_batches, (start // archive_batch_size) + 1),
                total=total_archive_batches,
                stage_percent=int(
                    (
                        min(total_archive_batches, (start // archive_batch_size) + 1)
                        / max(1, total_archive_batches)
                    )
                    * 100
                ),
            )
            break

        batch = hostnames[start : start + archive_batch_size]
        batched_input = "\n".join(batch) + "\n"
        current_batch = start // archive_batch_size + 1
        with ThreadPoolExecutor(max_workers=len(active_jobs)) as executor:
            futures = {
                executor.submit(
                    execute_command,
                    command,
                    min(max(1, int(timeout)), remaining_budget_seconds),
                    batched_input,
                    retry_policy,
                ): (
                    label,
                    time.monotonic(),
                    max(1, int(timeout)),
                    min(max(1, int(timeout)), remaining_budget_seconds),
                )
                for label, command, timeout, retry_policy in active_jobs
            }
            for future in as_completed(futures):
                label, started, configured_timeout_seconds, timeout_seconds = futures[future]
                try:
                    outcome = future.result()
                except Exception as exc:
                    duration = round(time.monotonic() - started, 1)
                    aggregate_meta[label]["duration_seconds"] += duration
                    aggregate_meta[label]["status"] = "error"
                    aggregate_meta[label]["error_count"] += 1
                    timeout_streak_by_provider[label] = timeout_streak_by_provider.get(label, 0) + 1
                    if timeout_streak_by_provider[label] >= max_timeout_streak:
                        disabled_providers.add(label)
                    percent = 59 + min(4, int((current_batch / total_archive_batches) * 4))
                    emit_collection_progress(
                        progress_callback,
                        (
                            f"{label} host-group {current_batch}/{total_archive_batches}: "
                            f"provider error ({exc})"
                        ),
                        percent,
                        processed=current_batch,
                        total=total_archive_batches,
                        stage_percent=int((current_batch / total_archive_batches) * 100),
                    )
                    continue
                output = outcome.stdout
                parsed_urls = apply_url_filters(parse_plain_lines(output), filters)
                new_urls = len(parsed_urls - urls)
                urls.update(parsed_urls)
                duration = round(outcome.duration_seconds or (time.monotonic() - started), 1)
                aggregate_meta[label]["duration_seconds"] += duration
                aggregate_meta[label]["new_urls"] += new_urls
                aggregate_meta[label]["attempt_count"] += max(1, int(outcome.attempt_count or 1))
                aggregate_meta[label]["configured_timeout_seconds"] = configured_timeout_seconds
                aggregate_meta[label]["effective_timeout_seconds"] = timeout_seconds
                aggregate_meta[label]["warning_messages"] = [
                    *aggregate_meta[label]["warning_messages"],
                    *[
                        warning
                        for warning in outcome.warning_messages
                        if warning not in aggregate_meta[label]["warning_messages"]
                    ],
                ]
                aggregate_meta[label]["timeout_events"] = [
                    *aggregate_meta[label]["timeout_events"],
                    *[
                        event
                        for event in outcome.warning_messages
                        if "timed out" in str(event or "").lower()
                        and event not in aggregate_meta[label]["timeout_events"]
                    ],
                ]

                if outcome.timed_out:
                    aggregate_meta[label]["timeout_count"] += 1
                    timeout_streak_by_provider[label] = timeout_streak_by_provider.get(label, 0) + 1
                else:
                    timeout_streak_by_provider[label] = 0

                if timeout_streak_by_provider[label] >= max_timeout_streak:
                    disabled_providers.add(label)
                    aggregate_meta[label]["status"] = "degraded_timeout"
                elif outcome.timed_out:
                    aggregate_meta[label]["status"] = "degraded_timeout"
                elif outcome.fatal:
                    aggregate_meta[label]["status"] = "error"
                    aggregate_meta[label]["error_count"] += 1
                elif output:
                    aggregate_meta[label]["status"] = "ok"
                else:
                    aggregate_meta[label]["status"] = "empty"
                percent = 59 + min(4, int((current_batch / total_archive_batches) * 4))
                effective_timeout_note = ""
                if timeout_seconds != configured_timeout_seconds:
                    effective_timeout_note = f" (configured {configured_timeout_seconds}s, clamped to {timeout_seconds}s)"
                emit_collection_progress(
                    progress_callback,
                    (
                        f"{label} host-group {current_batch}/{total_archive_batches}: "
                        f"+{new_urls} URLs, total {len(urls)}{effective_timeout_note}"
                    ),
                    percent,
                    processed=current_batch,
                    total=total_archive_batches,
                    stage_percent=int((current_batch / total_archive_batches) * 100),
                )
                if label in disabled_providers:
                    emit_collection_progress(
                        progress_callback,
                        (
                            f"{label} disabled after {timeout_streak_by_provider[label]} "
                            "timeout-like attempts"
                        ),
                        percent,
                        processed=current_batch,
                        total=total_archive_batches,
                        stage_percent=int((current_batch / total_archive_batches) * 100),
                    )

    return urls, aggregate_meta


__all__ = ["run_archive_jobs"]

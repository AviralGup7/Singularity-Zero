"""Adaptive active scanning stage.

Integrates the AdaptiveScanCoordinator with existing security probes
to provide intelligent, priority-based scanning that boosts correlated
targets when vulnerabilities are found.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from urllib.parse import urlparse

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.decision.adaptive_scan import AdaptiveScanCoordinator
from src.pipeline.runner_support import emit_progress

from .composite_probe import CompositeActiveProbe
from .probe_registry import (
    _build_response_cache,
    _load_active_probe_functions,
    _normalize_scan_targets,
)
from .probe_runners import _try_probe

logger = get_pipeline_logger(__name__)


async def run_active_scanning_adaptive(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    probe_loader: Any = _load_active_probe_functions,
) -> StageOutput:
    """Adaptive Stage: Active probing with dynamic prioritization and boosting."""
    stage_started = time.monotonic()

    # 1. Target Preparation
    live_hosts = set(ctx.live_hosts) if ctx.live_hosts else set()
    urls = set(ctx.urls) if ctx.urls else set()

    all_urls = _normalize_scan_targets([*list(urls), *list(live_hosts)])
    if not all_urls:
        logger.info("Adaptive active scan: no targets available, skipping")
        return StageOutput(
            stage_name="active_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=round(time.monotonic() - stage_started, 2),
            metrics={"status": "skipped", "reason": "no_targets"},
            state_delta={},
        )

    emit_progress("active_scan", f"Starting adaptive scan on {len(all_urls)} targets", 75)

    # 2. Resource Initialization
    try:
        probes = probe_loader()
        response_cache = _build_response_cache()
    except Exception as exc:
        logger.error("Failed to initialize active scan resources: %s", exc)
        return StageOutput(
            stage_name="active_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=round(time.monotonic() - stage_started, 2),
            error=str(exc),
            state_delta={},
        )

    # 3. Host-Level Probes (Run once per unique host to avoid redundancy)
    unique_hosts = {urlparse(url).netloc for url in all_urls}
    host_targets = [f"https://{host}" for host in unique_hosts if host]
    host_priority_items = [{"url": url} for url in host_targets]

    degraded_probes: list[dict[str, Any]] = []

    analysis_settings = getattr(config, "analysis", {}) if config is not None else {}
    try:
        probe_timeout_seconds = float(analysis_settings.get("active_probe_timeout_seconds", 180))
    except (TypeError, ValueError):
        probe_timeout_seconds = 180.0
    probe_timeout_seconds = max(30.0, probe_timeout_seconds)

    logger.info("Running host-level probes on %d unique hosts", len(unique_hosts))
    host_probe_names = ["cors", "trace", "options", "cloud_metadata"]
    host_tasks = [
        _try_probe(
            "cors",
            probes["cors_preflight_probe"],
            host_priority_items,
            response_cache,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
        _try_probe(
            "trace",
            probes["trace_method_probe"],
            host_priority_items,
            response_cache,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
        _try_probe(
            "options",
            probes["options_method_probe"],
            host_priority_items,
            response_cache,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
        _try_probe(
            "cloud_metadata",
            probes["cloud_metadata_active_probe"],
            host_targets,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
    ]
    host_results = await asyncio.gather(*host_tasks, return_exceptions=True)

    all_findings: list[dict[str, Any]] = []
    host_probe_errors: list[str] = []
    for probe_name, r in zip(host_probe_names, host_results, strict=False):
        if isinstance(r, BaseException):
            host_probe_errors.append(f"{probe_name}: {r.__class__.__name__}: {r}")
            logger.error("Host-level probe '%s' failed: %s", probe_name, r)
            continue
        if isinstance(r, tuple):
            _, findings, ok = r
            if ok:
                if findings:
                    all_findings.extend(findings)
            else:
                host_probe_errors.append(f"{probe_name}: probe failed or timed out")

    # 4. Adaptive Endpoint Probes
    batch_size = int(analysis_settings.get("adaptive_batch_size", 20))
    concurrency = int(analysis_settings.get("adaptive_concurrency", 5))

    coordinator = AdaptiveScanCoordinator(
        urls=all_urls,
        probe_fn=CompositeActiveProbe(
            probes,
            response_cache,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=degraded_probes,
        ),
        batch_size=batch_size,
        concurrency=concurrency,
        boost_on_findings=True,
    )

    logger.info("Starting AdaptiveScanCoordinator loop")
    batch_result = await coordinator.run()

    for result in batch_result.results:
        if result.findings:
            all_findings.extend(result.findings)

    # 5. Result Consolidation
    duration = round(time.monotonic() - stage_started, 2)
    metrics = {
        "status": "ok",
        "duration_seconds": duration,
        "targets_total": len(all_urls),
        "targets_scanned": batch_result.scanned,
        "findings_count": len(all_findings),
        "boosted_count": batch_result.boosted_count,
        "early_terminated": batch_result.early_terminated,
        "adaptive_batches": len(batch_result.results) // batch_size + 1,
        "host_probe_errors_count": len(host_probe_errors),
        "host_probe_errors_sample": host_probe_errors[:5],
        "degraded_probes": degraded_probes,
    }

    emit_progress(
        "active_scan",
        f"Adaptive scan complete: {len(all_findings)} findings on {batch_result.scanned} targets",
        90,
    )

    return StageOutput(
        stage_name="active_scan",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=duration,
        metrics=metrics,
        state_delta={"active_scan_findings": all_findings},
    )

"""Reconnaissance stages for the pipeline."""

from functools import partial
from typing import Any

from src.analysis.behavior.service import run_service_enrichment
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext
from src.core.utils import normalize_scope_entry
from src.pipeline.runner_support import (
    emit_progress,
    emit_url_progress,
)
from src.pipeline.services.pipeline_helpers import (
    build_stage_input_from_context,
)
from src.pipeline.services.services.recon_service import (
    run_parameter_extraction_stage,
    run_priority_ranking_stage,
    run_subdomain_enumeration_service,
)
from src.recon.live_hosts import probe_live_hosts
from src.recon.subdomains import enumerate_subdomains
from src.recon.urls import collect_urls

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

# Test seams
enumerate_subdomains = enumerate_subdomains


def _record_recon_failure(
    stage_name: str,
    ctx: PipelineContext,
    reason_code: str,
    error: str,
    details: dict[str, Any],
    duration_seconds: float,
    fatal: bool = False,
) -> None:
    """Record a reconnaissance failure in the context."""
    metrics = {
        "status": "failed",
        "reason": reason_code,
        "failure_reason_code": reason_code,
        "failure_reason": error,
        "error": error,
        "duration_seconds": round(duration_seconds, 2),
        "details": details,
        "fatal": fatal,
    }
    ctx.result.module_metrics[stage_name] = metrics
    if fatal:
        ctx.mark_stage_failed(stage_name, error)


def _tool_diagnostics(config: Any, tools: tuple[str, ...]) -> None:
    """Check if required tools are available."""
    # Simple diagnostic placeholder
    _ = (config, tools)


async def run_subdomain_enumeration(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage 1: Enumerate subdomains from scope entries."""
    try:
        emit_progress("subdomains", "Enumerating subdomains", 15)

        if stage_input is None:
            stage_input = build_stage_input_from_context("subdomains", config, ctx)

        stage_output = await run_subdomain_enumeration_service(
            stage_input,
            skip_crtsh=bool(getattr(args, "skip_crtsh", False)),
            refresh_cache=bool(getattr(args, "refresh_cache", False)),
        )

        if stage_output.outcome == StageOutcome.FAILED:
            # Handle failure side effects
            _record_recon_failure(
                stage_name="subdomains",
                ctx=ctx,
                reason_code=stage_output.reason,
                error=stage_output.error,
                details=dict(stage_output.metrics.get("details", {})),
                duration_seconds=stage_output.duration_seconds,
                fatal=True,
            )
            return stage_output

        # Success side effects
        subdomains = set(stage_output.state_delta.get("subdomains", []))
        emit_progress(
            "subdomains",
            f"Found {len(subdomains)} subdomains",
            28,
            status="running",
            stage_status="running",
            stage_percent=100,
            targets_done=len(subdomains),
            targets_scanning=0,
            targets_queued=0,
            event_trigger="recon_subdomains_discovered",
        )

        # Write to output store (side effect allowed in wrapper)
        ctx.output_store.write_subdomains(subdomains)

        return stage_output

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'subdomains' failed: %s", exc)
        fallback_subdomains = {
            normalize_scope_entry(entry).strip().lower()
            for entry in ctx.scope_entries
            if normalize_scope_entry(entry).strip()
        }
        _record_recon_failure(
            stage_name="subdomains",
            ctx=ctx,
            reason_code="subdomain_stage_exception",
            error=f"Subdomain enumeration failed: {exc}",
            details={"exception_type": exc.__class__.__name__},
            duration_seconds=0.0,
            fatal=True,
        )
        return StageOutput(
            stage_name="subdomains",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.0,
            error=str(exc),
            reason="subdomain_stage_wrapper_exception",
            state_delta={"subdomains": fallback_subdomains},
        )


from src.pipeline.services.services.recon_service import (
    run_live_hosts_service,
)


async def run_live_hosts(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage 2: Probe live hosts and run service enrichment."""
    try:
        emit_progress("live_hosts", "Probing live hosts", 36)

        # Diagnostics (side effect)
        _tool_diagnostics(config, ("httpx",))

        if stage_input is None:
            stage_input = build_stage_input_from_context("live_hosts", config, ctx)

        prober = partial(probe_live_hosts, config=config)

        async def enricher_wrapper(
            records: list[dict[str, Any]], context: Any
        ) -> tuple[list[dict[str, Any]], set[str], dict[str, Any]]:
            # run_service_enrichment is sync, so run in thread.
            import asyncio

            subdomains = set(context.get("result", {}).get("subdomains", []))
            return await asyncio.to_thread(
                run_service_enrichment,
                subdomains,
                records,
                config,
                runtime_budget_seconds=int(stage_input.runtime.get("timeout_seconds", 120)),
            )

        stage_output = await run_live_hosts_service(
            stage_input,
            prober=prober,
            enricher=enricher_wrapper,
            force_recheck=bool(getattr(args, "force_recheck", False)),
        )

        if stage_output.outcome == StageOutcome.FAILED:
            _record_recon_failure(
                stage_name="live_hosts",
                ctx=ctx,
                reason_code=stage_output.reason,
                error=stage_output.error,
                details=dict(stage_output.metrics.get("details", {})),
                duration_seconds=stage_output.duration_seconds,
                fatal=True,
            )
            return stage_output

        live_hosts = set(stage_output.state_delta.get("live_hosts", []))
        emit_progress(
            "live_hosts",
            f"Found {len(live_hosts)} live hosts",
            54,
            status="running",
            stage_status="running",
            targets_done=len(live_hosts),
            event_trigger="recon_live_hosts_discovered",
        )

        return stage_output

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'live_hosts' failed: %s", exc)
        _record_recon_failure(
            stage_name="live_hosts",
            ctx=ctx,
            reason_code="live_hosts_stage_exception",
            error=f"Live host probing failed: {exc}",
            details={"exception_type": exc.__class__.__name__},
            duration_seconds=0.0,
            fatal=True,
        )
        return StageOutput(
            stage_name="live_hosts",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.0,
            error=str(exc),
            reason="live_hosts_stage_wrapper_exception",
        )


from src.pipeline.services.services.recon_service import (
    run_url_collection_service,
)


async def run_url_collection(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage 3: Collect URLs from live hosts."""
    try:
        emit_progress("urls", "Collecting URLs", 56)

        # Diagnostics
        _tool_diagnostics(config, ("gau", "waybackurls", "katana"))

        if stage_input is None:
            stage_input = build_stage_input_from_context("urls", config, ctx)

        collector = partial(
            collect_urls, scope_entries=list(ctx.scope_entries), config=config
        )

        stage_output = await run_url_collection_service(
            stage_input,
            collector=collector,
            progress_callback=emit_url_progress,
        )

        if stage_output.outcome == StageOutcome.FAILED:
            _record_recon_failure(
                stage_name="urls",
                ctx=ctx,
                reason_code=stage_output.reason,
                error=stage_output.error,
                details=dict(stage_output.metrics.get("details", {})),
                duration_seconds=stage_output.duration_seconds,
                fatal=True,
            )
            return stage_output

        urls = set(stage_output.state_delta.get("urls", []))
        emit_progress(
            "urls",
            f"Collected {len(urls)} URLs",
            72,
            status="running",
            stage_status="running",
            targets_done=len(urls),
            event_trigger="recon_urls_collected",
        )

        return stage_output

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'urls' failed: %s", exc)
        _record_recon_failure(
            stage_name="urls",
            ctx=ctx,
            reason_code="urls_stage_exception",
            error=f"URL collection failed: {exc}",
            details={"exception_type": exc.__class__.__name__},
            duration_seconds=0.0,
            fatal=True,
        )
        return StageOutput(
            stage_name="urls",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.0,
            error=str(exc),
            reason="urls_stage_wrapper_exception",
        )


async def run_parameter_extraction(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage 4: Extract parameters, infer target profile, load history feedback."""
    try:
        emit_progress("parameters", "Extracting parameters", 74)
        if stage_input is None:
            stage_input = build_stage_input_from_context("parameters", config, ctx)
        stage_output = await run_parameter_extraction_stage(stage_input)
        if stage_output.outcome != StageOutcome.COMPLETED:
            return stage_output
        parameter_count = int(stage_output.artifacts.get("parameter_count", 0) or 0)
        url_count = int(stage_output.metrics.get("url_count", 0) or 0)
        emit_progress(
            "parameters",
            f"Extracted {parameter_count} parameters",
            78,
            stage_percent=100,
            status="running",
            stage_status="running",
            drop_off_input=url_count,
            drop_off_kept=parameter_count,
            drop_off_dropped=max(0, url_count - parameter_count),
            targets_done=parameter_count,
            targets_queued=0,
            targets_scanning=0,
            event_trigger="recon_parameters_extracted",
        )
        return stage_output
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'parameters' failed: %s", exc)
        return StageOutput(
            stage_name="parameters",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.0,
            error=str(exc),
            reason="parameter_stage_wrapper_exception",
            state_delta={
                "parameters": [],
                "target_profile": {},
                "history_feedback": {},
            },
        )


async def run_priority_ranking(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage 5: Score and rank priority endpoints."""
    try:
        emit_progress("priority", "Scoring priority endpoints", 82)
        if stage_input is None:
            stage_input = build_stage_input_from_context("ranking", config, ctx)
        stage_output = await run_priority_ranking_stage(stage_input)
        if stage_output.outcome != StageOutcome.COMPLETED:
            return stage_output
        priority_url_count = int(stage_output.artifacts.get("priority_url_count", 0) or 0)
        deep_analysis_count = int(stage_output.artifacts.get("deep_analysis_url_count", 0) or 0)
        selected_items = list(stage_output.state_delta.get("selected_priority_items", []) or [])
        emit_progress(
            "priority",
            f"Ranked {priority_url_count} priority endpoints",
            86,
            stage_percent=100,
            status="running",
            stage_status="running",
            drop_off_input=priority_url_count,
            drop_off_kept=deep_analysis_count,
            drop_off_dropped=max(0, priority_url_count - deep_analysis_count),
            high_value_target_count=deep_analysis_count,
            vulnerability_likelihood_score=min(
                1.0,
                max(
                    0.0,
                    float(
                        (
                            sum(float(item.get("score", 0.0) or 0.0) for item in selected_items)
                            / max(1, len(selected_items))
                        )
                        / 100.0
                    ),
                ),
            ),
            targets_done=deep_analysis_count,
            targets_queued=0,
            targets_scanning=0,
            event_trigger="recon_priority_ranked",
        )
        return stage_output
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'priority' failed: %s", exc)
        return StageOutput(
            stage_name="ranking",
            outcome=StageOutcome.FAILED,
            duration_seconds=0.0,
            error=str(exc),
            reason="priority_stage_wrapper_exception",
            state_delta={
                "ranked_priority_urls": [],
                "priority_urls": [],
                "selected_priority_items": [],
                "selection_meta": {},
                "deep_analysis_urls": [],
            },
        )

"""Reporting stage: screenshots, reports, dashboard, notifications."""

import asyncio
import time
from typing import Any

from src.analysis.intelligence.aggregator import attach_queue_replay_links
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.pipeline_logging import emit_info, emit_summary
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.core.plugins import resolve_plugin
from src.pipeline.runner_support import emit_progress
from src.pipeline.screenshots import capture_screenshots
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context
from src.reporting import build_artifact_diff

logger = get_pipeline_logger(__name__)

ENRICHMENT_PROVIDER = "enrichment_provider"
EXPORTER = "exporter"

async def run_reporting(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stages 9-11: Screenshot capture, report generation, dashboard generation."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("reporting", config, ctx)

    stage_started = time.monotonic()
    module_metrics: dict[str, Any] = {}

    try:
        emit_progress("reporting", "Generating report and dashboard", 96)
        post_started = time.monotonic()
        screenshots_task = asyncio.create_task(
            asyncio.to_thread(
                capture_screenshots,
                ctx.live_hosts,
                ctx.output_store.run_dir,
                config,
            )
        )

        # Resolve build_artifact_diff from registry? Not registered yet, but build_summary is.
        # Let's keep build_artifact_diff as a direct import for now as it is a core utility.
        diff_task = asyncio.create_task(
            asyncio.to_thread(
                build_artifact_diff,
                ctx.previous_run,
                {
                    "subdomains": ctx.subdomains,
                    "live_hosts": ctx.live_hosts,
                    "parameters": set(ctx.parameters)
                    if isinstance(ctx.parameters, list)
                    else ctx.parameters,
                    "priority_endpoints": set(ctx.priority_urls),
                },
                ctx.output_store.run_dir,
            )
        )
        screenshots, diff_summary_raw = await asyncio.gather(screenshots_task, diff_task)
        diff_summary = diff_summary_raw or {}
        module_metrics["screenshots"] = {
            "status": "ok",
            "duration_seconds": round(time.monotonic() - post_started, 2),
        }

        validation_summary = (
            ctx.validation_summary if isinstance(ctx.validation_summary, dict) else {}
        )
        validation_metric = dict(
            validation_summary.get("metrics") or validation_summary.get("metric") or {}
        )
        validation_metric["duration_seconds"] = round(time.monotonic() - post_started, 2)
        validation_metric["iterations"] = ctx.executed_iterations
        validation_metric["stop_reason"] = ctx.iterative_stop_reason
        module_metrics["validation_runtime"] = validation_metric
        verified_exploits = list(validation_summary.get("verified_exploits", []))

        # Resolve enrichment/intelligence providers from registry
        tech_summary_builder = resolve_plugin(ENRICHMENT_PROVIDER, "technology_summary")
        technology_summary = tech_summary_builder(ctx.analysis_results)

        endpoint_intel_builder = resolve_plugin(ENRICHMENT_PROVIDER, "endpoint_intelligence")
        endpoint_intelligence = endpoint_intel_builder(
            ctx.selected_priority_items,
            ctx.analysis_results,
            ctx.validation_summary,
        )

        attack_surface_builder = resolve_plugin(ENRICHMENT_PROVIDER, "attack_surface")
        attack_surface = attack_surface_builder(
            ctx.reportable_findings, ctx.selected_priority_items
        )

        trend_builder = resolve_plugin(ENRICHMENT_PROVIDER, "trend")
        trend_summary = trend_builder(ctx.previous_run, ctx.reportable_findings)

        next_steps_builder = resolve_plugin(ENRICHMENT_PROVIDER, "next_steps")
        next_steps = next_steps_builder(
            ctx.reportable_findings,
            ctx.target_profile,
            ctx.parameters,
            config.mode,
            technology_summary=technology_summary,
            validation_summary=ctx.validation_summary,
        )

        high_conf_builder = resolve_plugin(ENRICHMENT_PROVIDER, "high_confidence_shortlist")
        high_confidence_shortlist = high_conf_builder(
            ctx.reportable_findings,
            limit=int(config.review.get("high_confidence_shortlist_limit", 5)),
        )

        manual_queue_builder = resolve_plugin(ENRICHMENT_PROVIDER, "manual_verification_queue")
        manual_verification_queue = manual_queue_builder(
            ctx.reportable_findings,
            limit=int(config.review.get("manual_verification_limit", 8)),
        )

        correlation_builder = resolve_plugin(ENRICHMENT_PROVIDER, "cross_finding_correlation")
        cross_finding_correlation = correlation_builder(
            ctx.reportable_findings,
            limit=int(config.review.get("cross_finding_correlation_limit", 15)),
        )

        vrt_coverage_builder = resolve_plugin(ENRICHMENT_PROVIDER, "p1_vrt_coverage")
        vrt_coverage = vrt_coverage_builder(config)

        summary_builder = resolve_plugin(EXPORTER, "summary")
        summary = summary_builder(
            config.target_name,
            ctx.scope_entries,
            ctx.subdomains,
            ctx.live_records,
            ctx.urls,
            ctx.parameters,
            set(ctx.priority_urls),
            ctx.selected_priority_items,
            screenshots,
            ctx.analysis_results,
            ctx.reportable_findings,
            ctx.tool_status,
            ctx.module_metrics,
            attack_surface,
            ctx.target_profile,
            technology_summary,
            endpoint_intelligence,
            trend_summary,
            next_steps,
            high_confidence_shortlist,
            manual_verification_queue,
            cross_finding_correlation,
            vrt_coverage,
            verified_exploits,
            validation_summary,
            ctx.campaign_summary,
            config.review,
            config.extensions,
            ctx.started_at,
            ctx.previous_run,
            ctx.flow_manifest,
        )
        attach_queue_replay_links(
            summary.get("manual_verification_queue", []),
            target_name=config.target_name,
            run_name=ctx.output_store.run_dir.name,
        )
        ctx.output_store.persist_outputs(
            summary,
            diff_summary,
            screenshots,
            ctx.analysis_results,
            ctx.merged_findings,
        )

        generate_report = resolve_plugin(EXPORTER, "run_report")
        await asyncio.to_thread(
            generate_report,
            ctx.output_store.run_dir,
            summary,
            diff_summary,
            screenshots,
            set(ctx.deep_analysis_urls),
            ctx.parameters,
            ctx.analysis_results,
        )

        build_index = resolve_plugin(EXPORTER, "dashboard_index")
        await asyncio.to_thread(build_index, ctx.output_store.target_root)
        emit_progress("completed", "Run complete", 100)

        emit_summary(summary)
        emit_info(f"Artifacts written to: {ctx.output_store.run_dir}")
        emit_info(f"Run report: {ctx.output_store.run_dir / 'report.html'}")
        emit_info(f"Dashboard index: {ctx.output_store.target_root / 'index.html'}")

        # Notifications and Learning are now handled by event subscribers
        # listening for PIPELINE_COMPLETE and FINDING_CREATED events.

        module_metrics["reporting"] = {"exit_code": 0}
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="reporting",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics=module_metrics,
            state_delta={
                "screenshots": screenshots,
                "diff_summary": diff_summary,
            },
        )

    except Exception as exc:
        logger.exception("Stage reporting failed: %s", exc)
        ctx.mark_stage_failed("reporting", str(exc))
        module_metrics["reporting"] = {"exit_code": 1}
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="reporting",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics=module_metrics,
            state_delta={},
        )

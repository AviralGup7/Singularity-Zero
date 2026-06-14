"""Reconnaissance stages for the pipeline."""

import asyncio
import os
from functools import partial
from typing import Any, cast

from src.analysis.behavior.service import run_service_enrichment
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import (
    emit_progress,
    emit_stage_summary,
    emit_url_progress,
)
from src.pipeline.services.pipeline_helpers import (
    build_stage_input_from_context,
)
from src.pipeline.services.services.recon_service import (
    run_live_hosts_service,
    run_parameter_extraction_stage,
    run_priority_ranking_stage,
    run_subdomain_enumeration_service,
    run_url_collection_service,
    run_waf_detection_service,
)
from src.recon.live_hosts import probe_live_hosts
from src.recon.subdomains import enumerate_subdomains
from src.recon.urls import collect_urls

# Test seams
enumerate_subdomains = enumerate_subdomains
_DEFAULT_PROBE_LIVE_HOSTS = probe_live_hosts
_DEFAULT_COLLECT_URLS = collect_urls


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
    import shutil

    tools_config = getattr(config, "tools", {}) if config is not None else {}
    if not isinstance(tools_config, dict):
        tools_config = {}

    missing_tools = []
    for tool in tools:
        if tools_config.get(tool, True):
            if shutil.which(tool) is None:
                missing_tools.append(tool)

    if missing_tools:
        raise RuntimeError(
            f"Required external tools are missing from PATH: {', '.join(missing_tools)}. "
            "Please install them or disable them in the configuration."
        )


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
            return cast(StageOutput, stage_output)

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
            telemetry_event_type="recon.subdomains.completed",
            artifact_type="subdomain",
            telemetry_items=sorted(subdomains),
        )

        emit_stage_summary(
            "subdomains",
            {
                "subdomains_found": len(subdomains),
                "duration": stage_output.duration_seconds,
                "status": "ok",
            },
        )

        # Write to output store (side effect allowed in wrapper)
        if ctx.output_store is not None:
            ctx.output_store.write_subdomains(subdomains)
        else:
            logger.warning(
                "Stage 'subdomains': ctx.output_store is None, skipping write_subdomains()"
            )

        return cast(StageOutput, stage_output)

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'subdomains' failed: %s", exc)
        # NOTE: We deliberately do not fall back to ``ctx.scope_entries``
        # here. Silently substituting scope entries as "subdomains" hides
        # the real failure from downstream stages and leads to nonsense
        # results in the live_hosts/urls stages. Instead, return an empty
        # set with a clear failure status.
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
            state_delta={"subdomains": set()},
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

        prober = None
        if probe_live_hosts is not _DEFAULT_PROBE_LIVE_HOSTS:
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
            enricher=cast(Any, enricher_wrapper),
            force_recheck=bool(getattr(args, "force_recheck", False)),
            pipeline_config=config,
        )

        if stage_output.outcome == StageOutcome.FAILED:
            # Write empty output files so validation passes (zero live hosts is valid)
            if ctx.output_store is not None:
                ctx.output_store.write_live_hosts([], set())
            _record_recon_failure(
                stage_name="live_hosts",
                ctx=ctx,
                reason_code=stage_output.reason,
                error=stage_output.error,
                details=dict(stage_output.metrics.get("details", {})),
                duration_seconds=stage_output.duration_seconds,
                fatal=True,
            )
            return cast(StageOutput, stage_output)

        live_hosts = set(stage_output.state_delta.get("live_hosts", []))
        emit_progress(
            "live_hosts",
            f"Found {len(live_hosts)} live hosts",
            54,
            status="running",
            stage_status="running",
            targets_done=len(live_hosts),
            event_trigger="recon_live_hosts_discovered",
            telemetry_event_type="recon.live_hosts.completed",
            artifact_type="live_host",
            telemetry_items=sorted(live_hosts),
        )

        emit_stage_summary(
            "live_hosts",
            {
                "live_hosts_found": len(live_hosts),
                "records_found": len(stage_output.state_delta.get("live_records", [])),
                "duration": stage_output.duration_seconds,
                "status": "ok",
            },
        )

        # Write to output store (side effect allowed in wrapper)
        if ctx.output_store is not None:
            live_records = stage_output.state_delta.get("live_records", [])
            ctx.output_store.write_live_hosts(live_records, live_hosts)
        else:
            logger.warning(
                "Stage 'live_hosts': ctx.output_store is None, skipping write_live_hosts()"
            )

        return cast(StageOutput, stage_output)

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


async def run_waf_detection(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage 2.5: Detect WAF/CDN protection on live hosts."""
    try:
        emit_progress("waf", "Detecting WAF/CDN protection", 55)
        if stage_input is None:
            stage_input = build_stage_input_from_context("waf", config, ctx)

        stage_output = await run_waf_detection_service(
            stage_input, timeout=float(config.recon.get("waf_timeout", 10.0))
        )

        if stage_output.outcome == StageOutcome.COMPLETED:
            waf_findings = stage_output.state_delta.get("waf_findings", [])
            emit_progress("waf", f"Found {len(waf_findings)} WAF/CDN signatures", 56)

            emit_stage_summary(
                "waf",
                {
                    "findings_count": len(waf_findings),
                    "providers": sorted(list({f["provider"] for f in waf_findings})),
                    "duration": stage_output.duration_seconds,
                    "status": "ok",
                },
            )

        return cast(StageOutput, stage_output)
    except Exception as exc:
        logger.error("Stage 'waf' failed: %s", exc)
        return StageOutput(
            stage_name="waf", outcome=StageOutcome.FAILED, duration_seconds=0.0, error=str(exc)
        )


logger = get_pipeline_logger(__name__)


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

        collector = None
        if collect_urls is not _DEFAULT_COLLECT_URLS:
            collector = partial(collect_urls, scope_entries=list(ctx.scope_entries), config=config)

        stage_output = await run_url_collection_service(
            stage_input,
            collector=collector,
            progress_callback=emit_url_progress,
            pipeline_config=config,
        )

        if stage_output.outcome == StageOutcome.FAILED:
            # Write empty output file so validation passes (zero urls is valid)
            if ctx.output_store is not None:
                ctx.output_store.write_urls(set())
            _record_recon_failure(
                stage_name="urls",
                ctx=ctx,
                reason_code=stage_output.reason,
                error=stage_output.error,
                details=dict(stage_output.metrics.get("details", {})),
                duration_seconds=stage_output.duration_seconds,
                fatal=True,
            )
            return cast(StageOutput, stage_output)

        urls = set(stage_output.state_delta.get("urls", []))

        # GAP 8: Capture CollectorMeta for telemetry / observability.
        collector_meta = stage_output.state_delta.get("collector_meta")
        if collector_meta:
            ctx.result.url_stage_meta.setdefault("collector_meta", []).append(collector_meta)

        emit_stage_summary(
            "urls",
            {
                "urls_collected": len(urls),
                "duration": stage_output.duration_seconds,
                "status": "ok",
            },
        )

        # ──────────────────────────────────────────────────────────
        # Category 2: Advanced Reconnaissance & Asset Discovery Integrations
        # ──────────────────────────────────────────────────────────
        try:
            import json
            from pathlib import Path

            target_name = config.target_name
            target_root = (
                ctx.output_store.target_root
                if ctx.output_store
                else Path(config.output_dir) / target_name
            )
            target_root.mkdir(parents=True, exist_ok=True)

            logger.info(
                "Initializing Category 2 Advanced Recon integrations for target %s", target_name
            )

            # 1. Cloud Bucket & Asset Enumeration (Multi-Cloud Recon)
            from src.recon.cloud_recon import CloudBucketScanner

            bucket_scanner = CloudBucketScanner()
            emit_progress("urls", "Scanning Cloud storage buckets", 70)
            # ``run_scan_sync`` is a blocking call that issues dozens of
            # HTTPS requests to AWS/GCP/Azure enumeration endpoints.
            # Running it inline blocks the event loop and stalls every
            # other concurrent stage (URL collection, parameter
            # extraction, …). Push it to a worker thread.
            bucket_findings = await asyncio.to_thread(bucket_scanner.run_scan_sync, target_name)
            logger.info(
                "Cloud bucket scan found %d exposed/secure containers", len(bucket_findings)
            )

            # Atomic write: write to a temp file, fsync, ``os.replace``
            # # so a crash mid-write never leaves a half-written
            # ``cloud_buckets.json`` for downstream stages to consume.
            bucket_path = target_root / "cloud_buckets.json"
            tmp_path = bucket_path.with_suffix(bucket_path.suffix + ".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(bucket_findings, f, indent=2, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, bucket_path)

            # 2. Automatic API Schema Reconstruction
            from src.recon.api_reconstructor import ApiSchemaReconstructor

            reconstructor = ApiSchemaReconstructor(target_root)
            reconstructor.reconstruct_spec(target_name, urls)
            logger.info("OpenAPI 3.0 specification successfully compiled inside %s", target_root)

            # 3. Continuous Discovery & Drift Detection
            from src.recon.drift_detection import DriftDetector

            detector = DriftDetector(target_root)

            # Gather current recon metrics
            current_snapshot = {
                "subdomains": sorted(list(ctx.result.subdomains)),
                "live_hosts": sorted(list(ctx.result.live_hosts)),
                "open_ports": sorted(
                    list(
                        {
                            f"{r.get('hostname') or r.get('ip') or ''}:{r.get('port') or ''}"
                            for r in ctx.result.live_records
                            if r.get("port")
                        }
                    )
                ),
                "urls": sorted(list(urls)),
            }
            drift_report = detector.compute_drift(target_name, current_snapshot)
            if drift_report.get("has_drift", False):
                summary = detector.render_cli_summary(drift_report)
                logger.warning("Recon asset drift detected for %s:\n%s", target_name, summary)
            else:
                logger.info(
                    "No recon asset drift detected. Core profile matches historical snapshot."
                )

        except Exception as exc:
            logger.exception("Category 2 Advanced Recon integrations failed: %s", exc)

        emit_progress(
            "urls",
            f"Collected {len(urls)} URLs",
            72,
            status="running",
            stage_status="running",
            targets_done=len(urls),
            event_trigger="recon_urls_collected",
            telemetry_event_type="recon.urls.completed",
            artifact_type="url",
            telemetry_items=sorted(urls)[:500],
        )

        # Write to output store (side effect allowed in wrapper)
        if ctx.output_store is not None:
            ctx.output_store.write_urls(urls)
        else:
            logger.warning(
                "Stage 'urls': ctx.output_store is None, skipping write_urls()"
            )

        return cast(StageOutput, stage_output)

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
            return cast(StageOutput, stage_output)
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

        emit_stage_summary(
            "parameters",
            {
                "parameters_extracted": parameter_count,
                "target_profile": stage_output.state_delta.get("target_profile", {}),
                "duration": stage_output.duration_seconds,
                "status": "ok",
            },
        )

        return cast(StageOutput, stage_output)
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'parameters' failed: %s", exc)
        # Mirror the behaviour of the other recon failure paths: record the
        # failure in the context so downstream stages and post-run reporting
        # see the parameters stage as failed (previously this branch silently
        # returned a FAILED ``StageOutput`` without touching ``ctx``).
        _record_recon_failure(
            stage_name="parameters",
            ctx=ctx,
            reason_code="parameter_stage_exception",
            error=f"Parameter extraction failed: {exc}",
            details={"exception_type": exc.__class__.__name__},
            duration_seconds=0.0,
            fatal=True,
        )
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
            return cast(StageOutput, stage_output)
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

        # Write to output store for regression tracking
        priority_urls = stage_output.state_delta.get("priority_urls", [])
        ranked_priority_urls = stage_output.state_delta.get("ranked_priority_urls", [])
        ctx.output_store.write_priority_endpoints(priority_urls)
        ctx.output_store.write_priority_scores(ranked_priority_urls)

        emit_stage_summary(
            "priority",
            {
                "priority_urls": priority_url_count,
                "deep_analysis_urls": deep_analysis_count,
                "avg_score": round(
                    sum(f["score"] for f in selected_items) / max(1, len(selected_items)), 2
                ),
                "duration": stage_output.duration_seconds,
                "status": "ok",
            },
        )

        # Wire GAP 1: Generate structured recon candidates from ctx state
        # so downstream intelligence/enrichment can consume them.
        try:
            from src.recon.standardize import standardize_recon_outputs

            ctx.recon_candidates = [
                {
                    "kind": c.kind,
                    "value": c.value,
                    "source": c.source,
                    "host": c.host,
                    "url": c.url,
                    "score": c.score,
                    "metadata": c.metadata,
                }
                for c in standardize_recon_outputs(
                    subdomains=ctx.result.subdomains,
                    live_hosts=ctx.result.live_hosts,
                    urls=ctx.result.urls,
                    ranked_urls=ctx.result.ranked_priority_urls,
                    parameters=ctx.result.parameters,
                )
            ]
        except Exception as exc:
            logger.debug("Failed to generate recon_candidates: %s", exc)

        # Wire GAP 2: Store enhanced recon extras into PipelineContext
        # so downstream stages can access port_scan, spa, graphql, etc.
        try:
            extras: dict[str, Any] = {}
            # Collect extras from URL collection stage if available
            url_stage_extras = ctx.result.url_stage_meta.get("extras", {})
            if isinstance(url_stage_extras, dict):
                extras.update(url_stage_extras)
            ctx.recon_extras = extras
        except Exception as exc:
            logger.debug("Failed to populate recon_extras: %s", exc)

        return cast(StageOutput, stage_output)
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'priority' failed: %s", exc)
        return cast(
            StageOutput,
            StageOutput(
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
            ),
        )

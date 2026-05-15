"""Network-focused recon stage implementations.

This package provides implementations for network recon stages.
Public API:
- run_live_hosts_impl
- run_url_collection_impl
"""

import asyncio
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutput
from src.core.models.stage_result import PipelineContext

from .async_utils import _run_sync_with_heartbeat
from .live_hosts_orchestrator import LiveHostsOrchestrator
from .url_collection_orchestrator import UrlCollectionOrchestrator


async def run_live_hosts_impl(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    emit_progress_func: Any,
    probe_live_hosts_func: Any,
    run_service_enrichment_func: Any,
    tool_diagnostics_func: Any,
    record_recon_failure_func: Any,
) -> StageOutput:
    """Stage 2 implementation: Probe live hosts and run service enrichment."""
    orchestrator = LiveHostsOrchestrator(
        args=args,
        config=config,
        ctx=ctx,
        emit_progress_func=emit_progress_func,
        probe_live_hosts_func=probe_live_hosts_func,
        run_service_enrichment_func=run_service_enrichment_func,
        tool_diagnostics_func=tool_diagnostics_func,
        record_recon_failure_func=record_recon_failure_func,
    )
    return await orchestrator.run()


async def run_url_collection_impl(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    emit_progress_func: Any,
    emit_url_progress_func: Any,
    collect_urls_func: Any,
    resolve_cached_stage_func: Any,
    load_cached_set_func: Any,
    save_cached_set_func: Any,
    load_cached_json_func: Any,
    save_cached_json_func: Any,
    validate_recon_payload_func: Any,
    tool_diagnostics_func: Any,
    record_recon_failure_func: Any,
) -> StageOutput:
    """Stage 3 implementation: Collect URLs from live hosts."""
    orchestrator = UrlCollectionOrchestrator(
        args=args,
        config=config,
        ctx=ctx,
        emit_progress_func=emit_progress_func,
        emit_url_progress_func=emit_url_progress_func,
        collect_urls_func=collect_urls_func,
        resolve_cached_stage_func=resolve_cached_stage_func,
        load_cached_set_func=load_cached_set_func,
        save_cached_set_func=save_cached_set_func,
        load_cached_json_func=load_cached_json_func,
        save_cached_json_func=save_cached_json_func,
        validate_recon_payload_func=validate_recon_payload_func,
        tool_diagnostics_func=tool_diagnostics_func,
        record_recon_failure_func=record_recon_failure_func,
    )
    return await orchestrator.run()

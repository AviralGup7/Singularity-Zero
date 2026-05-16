from __future__ import annotations

import asyncio
import time
from typing import Any, cast

from beartype import beartype

from src.core.contracts.capabilities import (
    EnrichmentProviderProtocol,
    LiveHostProberProtocol,
    UrlCollectorProtocol,
)
from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.middleware import ScopeValidator
from src.core.utils import normalize_scope_entry
from src.recon.ranking_support import load_history_feedback, select_deep_analysis_targets
from src.recon.scoring import infer_target_profile, rank_urls
from src.recon.subdomains import enumerate_subdomains
from src.recon.urls import extract_parameters


@beartype
async def run_url_collection_service(
    stage_input: StageInput,
    *,
    collector: UrlCollectorProtocol,
    progress_callback: Any | None = None,
) -> StageOutput:
    """Pure service implementation for URL collection with strict type guards."""
    started = time.monotonic()
    state = _state(stage_input)

    live_hosts = set(state.get("live_hosts", []) or [])

    try:
        urls = await asyncio.to_thread(
            collector,
            sorted(list(live_hosts)),
            timeout_seconds=int(stage_input.runtime.get("timeout_seconds", 120)),
            progress_callback=progress_callback,
        )

        duration = round(time.monotonic() - started, 2)
        metrics = {
            "status": "ok",
            "duration_seconds": duration,
            "url_count": len(urls),
        }

        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics=metrics,
            state_delta={"urls": set(urls)},
        )
    except Exception as exc:
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.FAILED,
            duration_seconds=time.monotonic() - started,
            error=str(exc),
            reason="url_collection_failed",
            state_delta={},
        )

@beartype
async def run_live_hosts_service(
    stage_input: StageInput,
    *,
    prober: LiveHostProberProtocol,
    enricher: EnrichmentProviderProtocol | None = None,
    force_recheck: bool = False,
) -> StageOutput:
    """Pure service implementation for live host probing with strict type guards."""
    started = time.monotonic()
    state = _state(stage_input)

    subdomains = set(state.get("subdomains", []) or [])
    if not subdomains:
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.0,
            metrics={"status": "empty", "reason": "no_subdomains"},
            state_delta={"live_hosts": set(), "live_records": []},
        )

    try:
        # 1. Probing
        live_records, live_hosts = await asyncio.to_thread(
            prober,
            subdomains,
            timeout_seconds=int(stage_input.runtime.get("timeout_seconds", 120)),
            force_recheck=force_recheck,
        )

        # 2. Enrichment
        enrichment_delta: dict[str, Any] = {}
        if enricher and live_records:
            enrichment_result = await enricher(live_records, stage_input.state_snapshot)
            if isinstance(enrichment_result, tuple):
                live_records = enrichment_result[0]
                if len(enrichment_result) > 1:
                    live_hosts = set(enrichment_result[1])
                if len(enrichment_result) > 2:
                    enrichment_delta["service_results"] = enrichment_result[2]
            else:
                live_records = enrichment_result

        duration = round(time.monotonic() - started, 2)
        metrics = {
            "status": "ok",
            "duration_seconds": duration,
            "live_count": len(live_hosts),
            "record_count": len(live_records),
        }

        state_delta = {
            "live_hosts": set(live_hosts),
            "live_records": list(live_records),
        }
        state_delta.update(enrichment_delta)

        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics=metrics,
            state_delta=state_delta,
        )
    except Exception as exc:
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.FAILED,
            duration_seconds=time.monotonic() - started,
            error=str(exc),
            reason="live_hosts_probing_failed",
            state_delta={"live_hosts": set(), "live_records": []},
        )

@beartype
@beartype
@beartype
async def run_subdomain_enumeration_service(
    stage_input: StageInput,
    *,
    skip_crtsh: bool = False,
    refresh_cache: bool = False,
) -> StageOutput:
    """Pure service implementation for subdomain enumeration with strict type guards."""
    started = time.monotonic()
    state = _state(stage_input)

    scope_entries = list(stage_input.pipeline.scope_entries)
    seed_roots = {
        normalize_scope_entry(entry).strip().lower()
        for entry in scope_entries
        if normalize_scope_entry(entry).strip()
    }

    discovery_enabled = bool(state.get("discovery_enabled", True))

    # Initialize state_delta
    state_delta: dict[str, Any] = {
        "subdomains": set(),
        "module_metrics": {},
    }

    if not discovery_enabled:
        subdomains = set(seed_roots)
        state_delta["subdomains"] = subdomains
        metrics = {
            "status": "skipped",
            "duration_seconds": 0.0,
            "reason": "discovery_tools_disabled",
        }
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.COMPLETED,
            duration_seconds=0.0,
            metrics=metrics,
            state_delta=state_delta,
        )

    if not seed_roots:
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.FAILED,
            duration_seconds=0.0,
            error="No valid scope roots were available after normalization.",
            reason="empty_scope_entries",
        )

    try:
        enumerated_subdomains = await asyncio.to_thread(
            enumerate_subdomains, scope_entries, stage_input.runtime, skip_crtsh
        )
        scope_hosts = {
            entry.strip().lower()
            for entry in scope_entries
            if str(entry).strip()
        }
        scope_hosts.update(seed_roots)
        scope_validator = ScopeValidator(scope_hosts)
        scoped_subdomains = {
            sub
            for sub in enumerated_subdomains
            if scope_validator.check_hostname(str(sub)).allowed
        }
        excluded_subdomains = sorted(set(enumerated_subdomains) - scoped_subdomains)

        if not scoped_subdomains:
            return StageOutput(
                stage_name=stage_input.stage_name,
                outcome=StageOutcome.FAILED,
                duration_seconds=time.monotonic() - started,
                error="No in-scope subdomains were available after sensitive-scope filtering.",
                reason="no_subdomains_after_scope_filter",
            )

        discovered_non_seed = {sub for sub in scoped_subdomains if sub not in seed_roots}
        duration = round(time.monotonic() - started, 2)
        metrics = {
            "status": "ok",
            "duration_seconds": duration,
            "details": {
                "scope_seed_count": len(seed_roots),
                "discovered_count": len(enumerated_subdomains),
                "sensitive_scope_excluded_count": len(excluded_subdomains),
                "sensitive_scope_excluded": excluded_subdomains[:50],
                "discovered_non_seed_count": len(discovered_non_seed),
            },
        }
        state_delta["subdomains"] = scoped_subdomains
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics=metrics,
            state_delta=state_delta,
        )
    except Exception as exc:
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.FAILED,
            duration_seconds=time.monotonic() - started,
            error=str(exc),
            reason="subdomain_enumeration_failed",
            state_delta={"subdomains": set(seed_roots)},
        )

@beartype
@beartype
@beartype
async def run_parameter_extraction_stage(stage_input: StageInput) -> StageOutput:
    """Service entry point for parameter extraction with strict type guards."""
    started = time.monotonic()
    state = _state(stage_input)
    urls = set(state.get("urls", []) or [])
    previous_run = state.get("previous_run")
    try:
        parameters_task = asyncio.to_thread(extract_parameters, urls)
        target_profile_task = asyncio.to_thread(infer_target_profile, urls)
        history_feedback_task = asyncio.to_thread(load_history_feedback, previous_run)
        parameters, target_profile, history_feedback = await asyncio.gather(
            parameters_task,
            target_profile_task,
            history_feedback_task,
        )
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.COMPLETED,
            duration_seconds=time.monotonic() - started,
            metrics={
                "status": "ok",
                "parameter_count": len(parameters),
                "url_count": len(urls),
            },
            artifacts={
                "parameter_count": len(parameters),
            },
            state_delta={
                "parameters": sorted(parameters),
                "target_profile": target_profile,
                "history_feedback": history_feedback,
            },
        )
    except Exception as exc:
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.FAILED,
            duration_seconds=time.monotonic() - started,
            error=str(exc),
            reason="parameter_extraction_failed",
            metrics={
                "status": "failed",
                "error": str(exc),
            },
            state_delta={
                "parameters": [],
                "target_profile": {},
                "history_feedback": {},
            },
        )

@beartype
@beartype
@beartype
async def run_priority_ranking_stage(stage_input: StageInput) -> StageOutput:
    """Service entry point for priority ranking with strict type guards."""
    started = time.monotonic()
    state = _state(stage_input)
    runtime = _runtime(stage_input)

    urls = set(state.get("urls", []) or [])
    target_profile = dict(state.get("target_profile", {}) or {})
    history_feedback = dict(state.get("history_feedback", {}) or {})

    filters = dict(runtime.get("filters", {}) or {})
    scoring = dict(runtime.get("scoring", {}) or {})
    mode = str(runtime.get("mode", "default") or "default")
    analysis = dict(runtime.get("analysis", {}) or {})

    try:
        ranked_priority_urls = await asyncio.to_thread(
            rank_urls,
            urls,
            filters,
            scoring,
            mode,
            target_profile,
            cast(Any, history_feedback),
        )
        priority_urls = [item.get("url", "") for item in ranked_priority_urls if item.get("url")]
        selected_priority_items, selection_meta = await asyncio.to_thread(
            select_deep_analysis_targets,
            ranked_priority_urls,
            analysis,
            mode,
        )
        deep_analysis_urls = [
            str(item.get("url", "")) for item in selected_priority_items if item.get("url")
        ]

        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.COMPLETED,
            duration_seconds=time.monotonic() - started,
            metrics={
                "status": "ok",
                "selected_for_deep_analysis": max(selection_meta.get("selected_count", 0), 0),
                "selection_meta": selection_meta,
            },
            artifacts={
                "priority_url_count": len(priority_urls),
                "deep_analysis_url_count": len(deep_analysis_urls),
            },
            state_delta={
                "ranked_priority_urls": ranked_priority_urls,
                "priority_urls": priority_urls,
                "selected_priority_items": selected_priority_items,
                "selection_meta": selection_meta,
                "deep_analysis_urls": deep_analysis_urls,
            },
        )
    except Exception as exc:
        return StageOutput(
            stage_name=stage_input.stage_name,
            outcome=StageOutcome.FAILED,
            duration_seconds=time.monotonic() - started,
            error=str(exc),
            reason="priority_ranking_failed",
            metrics={
                "status": "failed",
                "error": str(exc),
            },
            state_delta={
                "ranked_priority_urls": [],
                "priority_urls": [],
                "selected_priority_items": [],
                "selection_meta": {},
                "deep_analysis_urls": [],
            },
        )

def _state(stage_input: StageInput) -> dict[str, Any]:
    return dict(stage_input.state_snapshot.get("result", {}) or {})

def _runtime(stage_input: StageInput) -> dict[str, Any]:
    return dict(stage_input.runtime or {})

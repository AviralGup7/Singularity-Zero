"""Active scanning stage — wires existing probe modules into an orchestrated stage using parallel groups."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

# Import modular components to expose them on the active_scan module level
# for backward compatibility and test monkeypatching.
from .probe_registry import (
    _build_priority_items,
    _build_response_cache,
    _load_active_probe_functions,
    _normalize_scan_targets,
)
from .probe_runners import (
    _run_fuzzing_suggestion_probe,
    _run_jwt_attack_suite,
    _try_probe,
)
from .probe_suites import (
    _run_auth_bypass_suite,
    _run_http_smuggling_suite,
    _run_json_probe_suite,
)

logger = get_pipeline_logger(__name__)


async def run_active_scanning(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: Active probing against ranked targets.

    Supports both legacy batch scanning and new adaptive scanning mode
    using CorrelationPriorityQueue and dynamic boosting.
    """
    if stage_input is None:
        stage_input = build_stage_input_from_context("active_scan", config, ctx)

    analysis_settings = getattr(config, "analysis", {}) if config is not None else {}
    if not isinstance(analysis_settings, dict):
        analysis_settings = {}

    adaptive_enabled = str(analysis_settings.get("adaptive_mode", "true")).lower() == "true"

    if adaptive_enabled:
        logger.info("Adaptive scan mode enabled (default)")
        from .active_scan_adaptive import run_active_scanning_adaptive

        return await run_active_scanning_adaptive(
            args,
            config,
            ctx,
            probe_loader=_load_active_probe_functions,
        )

    stage_started = time.monotonic()

    live_hosts: set[str] = set(ctx.live_hosts) if ctx.live_hosts else set()
    urls: set[str] = set(ctx.urls) if ctx.urls else set()
    ranked_items: list[dict[str, Any]] = (
        list(ctx.selected_priority_items) if ctx.selected_priority_items else []
    )

    if not live_hosts and not urls and not ranked_items:
        logger.info("Active scan: no targets available, skipping")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="active_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={
                "status": "skipped",
                "reason": "no_targets",
                "duration_seconds": duration,
            },
            state_delta={},
        )

    ranked_urls = [
        str(item.get("url", "")).strip()
        for item in ranked_items
        if isinstance(item, dict) and str(item.get("url", "")).strip()
    ]

    urls_l = _normalize_scan_targets([*list(urls), *ranked_urls])
    live_hosts_l = _normalize_scan_targets(list(live_hosts))
    host_probe_targets = live_hosts_l if live_hosts_l else urls_l

    url_priority_items = _build_priority_items(urls_l)
    host_priority_items = _build_priority_items(host_probe_targets)
    ranked_priority_items = ranked_items if ranked_items else url_priority_items

    emit_progress("active_scan", "Initializing active scanning probes", 75)

    all_findings: list[dict[str, Any]] = []
    probes_succeeded = 0
    probes_failed = 0
    probes_executed = 0

    analysis_settings = getattr(config, "analysis", {}) if config is not None else {}
    if not isinstance(analysis_settings, dict):
        analysis_settings = {}
    try:
        probe_timeout_seconds = float(analysis_settings.get("active_probe_timeout_seconds", 180))
    except TypeError, ValueError:
        probe_timeout_seconds = 180.0
    probe_timeout_seconds = max(30.0, probe_timeout_seconds)

    try:
        probes = _load_active_probe_functions()
    except (ImportError, TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.warning("Could not import active probe modules: %s", exc)
        ctx.mark_stage_failed("active_scan", f"Import failed: {exc}")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="active_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=f"Import failed: {exc}",
            metrics={
                "status": "error",
                "error": f"Import failed: {exc}",
                "duration_seconds": duration,
            },
            state_delta={},
        )

    try:
        response_cache = _build_response_cache()
        prefetch_targets = [
            url for url in [*urls_l, *host_probe_targets] if url.startswith(("http://", "https://"))
        ]
        if prefetch_targets:
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(response_cache.prefetch, prefetch_targets[:60]),
                    timeout=min(90.0, probe_timeout_seconds),
                )
            except (TimeoutError, OSError, TypeError, ValueError, RuntimeError) as exc:
                logger.warning("Active scan prefetch skipped after timeout/error: %s", exc)
    except Exception as exc:
        logger.warning("Could not initialize active scan response cache: %s", exc)
        ctx.mark_stage_failed("active_scan", f"Response cache init failed: {exc}")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="active_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=f"Response cache init failed: {exc}",
            metrics={
                "status": "error",
                "error": f"Response cache init failed: {exc}",
                "duration_seconds": duration,
            },
            state_delta={},
        )

    probe_errors: list[dict[str, Any]] = []

    async def gather_with_progress(
        tasks: list[Any],
        *,
        stage_name: str,
        progress_message: str,
        base_progress: int,
        progress_span: int,
        initial_processed: int,
        total_planned: int,
    ) -> list[Any]:
        completed = 0
        total_tasks = len(tasks)
        if not total_tasks:
            return []

        async def wrap_task(task: Any) -> Any:
            nonlocal completed
            try:
                res = await task
                return res
            finally:
                completed += 1
                current_processed = initial_processed + completed
                progress = base_progress + int((completed / total_tasks) * progress_span)
                emit_progress(
                    stage_name,
                    progress_message,
                    progress,
                    processed=current_processed,
                    total=total_planned,
                )

        wrapped_tasks = [wrap_task(task) for task in tasks]
        return await asyncio.gather(*wrapped_tasks, return_exceptions=True)

    def _run_probe(name: str, probe_fn: Any, *probe_args: Any, **kwargs: Any) -> Any:
        return _try_probe(
            name,
            probe_fn,
            *probe_args,
            timeout_seconds=probe_timeout_seconds,
            error_accumulator=probe_errors,
            **kwargs,
        )

    # Group 1: URL-focused probes (can run in parallel)
    group1 = [
        _run_probe("sqli", probes["sqli_safe_probe"], url_priority_items, response_cache),
        _run_probe("csrf", probes["csrf_active_probe"], url_priority_items, response_cache),
        _run_probe("jwt", probes["jwt_manipulation_probe"], url_priority_items, response_cache),
        _run_probe("xss", probes["xss_reflect_probe"], url_priority_items, response_cache, 8),
        _run_probe("ssrf", probes["ssrf_active_probe"], url_priority_items, response_cache, 6),
        _run_probe(
            "file_upload",
            probes["file_upload_active_probe"],
            url_priority_items,
            response_cache,
        ),
        _run_probe("oauth", probes["oauth_flow_analyzer"], url_priority_items, response_cache),
        _run_probe(
            "open_redirect",
            probes["open_redirect_active_probe"],
            url_priority_items,
            response_cache,
            6,
        ),
        _run_probe(
            "path_traversal",
            probes["path_traversal_active_probe"],
            url_priority_items,
            response_cache,
            6,
        ),
        _run_probe(
            "command_injection",
            probes["command_injection_active_probe"],
            url_priority_items,
            response_cache,
            6,
        ),
    ]

    # Fix Audit #32: Handoff passive IDOR candidates to active probe
    passive_idor_candidates = []
    if hasattr(ctx.result, "passive_findings"):
        idor_findings = ctx.result.passive_findings.get("idor_candidate_finder", [])
        for f in idor_findings:
            if f.get("url") and f.get("score", 0) >= 3:
                passive_idor_candidates.append({"url": f["url"], "passive_score": f["score"]})

    idor_active_targets = ranked_priority_items
    if passive_idor_candidates:
        # Merge passive candidates, prioritizing them
        seen_urls = {str(item.get("url")) for item in idor_active_targets}
        for candidate in passive_idor_candidates:
            if candidate["url"] not in seen_urls:
                idor_active_targets.insert(0, candidate)
                seen_urls.add(candidate["url"])

    # Group 2: IDOR, Race, HPP, WebSocket, GraphQL (ranked_items + URL focused)
    group2 = [
        _run_probe("idor", probes["idor_active_probe"], idor_active_targets, response_cache),
        _run_probe(
            "race",
            probes["race_condition_probe"],
            ranked_priority_items,
            response_cache,
            concurrent_requests=int(analysis_settings.get("race_concurrency", 10)),
        ),
        _run_probe("hpp", probes["hpp_active_probe"], url_priority_items, response_cache),
        _run_probe(
            "websocket",
            probes["websocket_message_probe"],
            url_priority_items,
            response_cache,
        ),
        _run_probe("graphql", probes["graphql_active_probe"], url_priority_items, response_cache),
        _run_probe(
            "xpath", probes["xpath_injection_active_probe"], url_priority_items, response_cache, 5
        ),
        _run_probe("ssti", probes["ssti_active_probe"], url_priority_items, response_cache, 6),
        _run_probe("xxe", probes["xxe_active_probe"], url_priority_items, response_cache, 5),
        _run_probe("nosql", probes["nosql_injection_probe"], url_priority_items, response_cache, 5),
        _run_probe(
            "auth_bypass",
            _run_auth_bypass_suite,
            url_priority_items,
            response_cache,
            12,
            probes=probes,
        ),
        _run_probe(
            "jwt_attacks",
            _run_jwt_attack_suite,
            url_priority_items,
            response_cache,
            2,
            probes=probes,
        ),
        _run_probe(
            "ldap",
            probes["ldap_injection_active_probe"],
            url_priority_items,
            response_cache,
            5,
        ),
        _run_probe(
            "deserialization",
            probes["deserialization_probe"],
            url_priority_items,
            response_cache,
            5,
        ),
        _run_probe("proxy_ssrf", probes["proxy_ssrf_probe"], url_priority_items, response_cache, 5),
        _run_probe(
            "host_header",
            probes["host_header_injection_probe"],
            url_priority_items,
            response_cache,
            5,
        ),
        _run_probe("crlf", probes["crlf_injection_probe"], url_priority_items, response_cache, 5),
        _run_probe("mutation", probes["run_mutation_tests"], urls_l, ranked_items),
        _run_probe("fuzzing_suggestions", _run_fuzzing_suggestion_probe, urls_l, 12, probes=probes),
        _run_probe("json", _run_json_probe_suite, urls_l, response_cache, probes=probes),
        _run_probe("response_diff", probes["response_diff_engine"], urls_l, response_cache),
    ]

    # Group 3: Host-focused probes
    group3 = [
        _run_probe("cors", probes["cors_preflight_probe"], host_priority_items, response_cache),
        _run_probe("trace", probes["trace_method_probe"], host_priority_items, response_cache),
        _run_probe("options", probes["options_method_probe"], host_priority_items, response_cache),
        _run_probe("cloud_metadata", probes["cloud_metadata_active_probe"], host_probe_targets),
        _run_probe(
            "http_smuggling",
            _run_http_smuggling_suite,
            host_priority_items,
            response_cache,
            probes=probes,
        ),
    ]

    total_probe_count = len(group1) + len(group2) + len(group3)

    results1 = await gather_with_progress(
        group1,
        stage_name="active_scan",
        progress_message="Running CSRF and injection probes",
        base_progress=75,
        progress_span=5,
        initial_processed=0,
        total_planned=total_probe_count,
    )

    for r in results1:
        if isinstance(r, BaseException):
            probes_failed += 1
            probes_executed += 1
        else:
            _, findings, ok = r
            probes_executed += 1
            if ok:
                probes_succeeded += 1
                all_findings.extend(findings)
            else:
                probes_failed += 1

    results2 = await gather_with_progress(
        group2,
        stage_name="active_scan",
        progress_message="Running GraphQL and cloud metadata probes",
        base_progress=80,
        progress_span=6,
        initial_processed=len(group1),
        total_planned=total_probe_count,
    )

    for r in results2:
        if isinstance(r, BaseException):
            probes_failed += 1
            probes_executed += 1
        else:
            _, findings, ok = r
            probes_executed += 1
            if ok:
                probes_succeeded += 1
                all_findings.extend(findings)
            else:
                probes_failed += 1

    results3 = await gather_with_progress(
        group3,
        stage_name="active_scan",
        progress_message="Running mutation/fuzzing probes",
        base_progress=86,
        progress_span=4,
        initial_processed=len(group1) + len(group2),
        total_planned=total_probe_count,
    )

    for r in results3:
        if isinstance(r, BaseException):
            probes_failed += 1
            probes_executed += 1
        else:
            _, findings, ok = r
            probes_executed += 1
            if ok:
                probes_succeeded += 1
                all_findings.extend(findings)
            else:
                probes_failed += 1

    # Deduplicate findings across probes (Fix Audit #27)
    dedup_findings: list[dict[str, Any]] = []
    seen_vulns: set[tuple] = set()

    for finding in all_findings:
        # Create a unique key for the finding: (url, category, issue_type/probes_hash)
        url = str(finding.get("url", ""))
        category = str(finding.get("category", ""))
        # Some findings use 'issues', some use 'finding'
        issues = tuple(sorted(finding.get("issues", [])))
        if not issues and "finding" in finding:
            issues = (finding["finding"],)

        vuln_key = (url, category, issues)
        if vuln_key not in seen_vulns:
            seen_vulns.add(vuln_key)
            dedup_findings.append(finding)

    # Build state_delta with deduplicated findings
    state_delta: dict[str, Any] = {
        "active_scan_findings": dedup_findings,
    }

    emit_progress(
        "active_scan",
        f"Active scan complete: {probes_succeeded}/{probes_executed} probes succeeded, {len(dedup_findings)} findings",
        90,
        processed=probes_executed,
        total=probes_executed,
    )

    duration = round(time.monotonic() - stage_started, 2)
    metrics = {
        "status": "ok" if probes_succeeded > 0 else "warning",
        "duration_seconds": duration,
        "probes_executed": probes_executed,
        "probes_succeeded": probes_succeeded,
        "probes_failed": probes_failed,
        "findings_count": len(all_findings),
        "parallel_groups": 3,
        "degraded_probes": probe_errors,
    }

    logger.info(
        "Active scan completed (parallel, 3 groups): %d/%d probes succeeded, %d findings (%.1fs)",
        probes_succeeded,
        probes_executed,
        len(all_findings),
        duration,
    )

    return StageOutput(
        stage_name="active_scan",
        outcome=StageOutcome.COMPLETED,
        duration_seconds=duration,
        metrics=metrics,
        state_delta=state_delta,
    )

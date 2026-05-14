"""Access control testing stage: automated authorization bypass detection.

Runs after intelligence merge, tests discovered endpoints for
authorization bypasses using the access control analyzers from src.analysis.
"""

import time
from typing import Any
from urllib.parse import urlparse

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


def _is_absolute_http_url(value: object) -> bool:
    parsed = urlparse(str(value or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _build_access_control_cache(config: Any) -> Any:
    from src.analysis.passive.runtime import RequestScheduler, ResponseCache

    analysis_settings = getattr(config, "analysis", {}) if config is not None else {}
    if not isinstance(analysis_settings, dict):
        analysis_settings = {}

    timeout_seconds = max(5, int(analysis_settings.get("timeout_seconds", 10)))
    max_bytes = max(10_000, int(analysis_settings.get("max_response_bytes", 120_000)))
    max_workers = max(1, int(analysis_settings.get("max_workers", 4)))

    scheduler = RequestScheduler(
        rate_per_second=2.0,
        capacity=2.0,
        adaptive_mode=False,
    )
    return ResponseCache(
        timeout_seconds=timeout_seconds,
        max_bytes=max_bytes,
        max_workers=max_workers,
        scheduler=scheduler,
        persistent_cache_path=None,
        cache_ttl_hours=1,
    )


def _findings_from_enforcement_results(results: list[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in results or []:
        if str(getattr(item, "result", "")).lower() not in {"bypassed", "partial"}:
            continue
        endpoint = str(getattr(item, "endpoint", "") or "").strip()
        if not _is_absolute_http_url(endpoint):
            continue
        findings.append(
            {
                "url": endpoint,
                "method": str(getattr(item, "method", "GET") or "GET"),
                "severity": "high",
                "confidence": 0.75,
                "category": "access_control",
                "title": "Authorization bypass indicator",
                "signals": [f"access_control_{str(getattr(item, 'result', 'partial')).lower()}"],
                "evidence": {
                    "test_context": str(getattr(item, "test_context", "")),
                    "details": str(getattr(item, "details", "")),
                },
                "explanation": str(getattr(item, "details", "")),
            }
        )
    return findings


async def run_access_control_testing(
    args: Any,
    config: Any,
    ctx: PipelineContext,
) -> StageOutput:
    """Stage: Automated authorization bypass detection.

    Tests endpoints with different auth contexts and compares responses
    to detect access control vulnerabilities.
    """
    stage_started = time.monotonic()
    state_delta: dict[str, Any] = {
        "module_metrics": {},
        "reportable_findings": [],
    }

    try:
        emit_progress(
            "access_control",
            "Running automated authorization bypass detection",
            92,
        )

        # Import access control analyzers from src.analysis
        analyze_access_control_async = None
        try:
            from src.analysis.checks.active.access_control_analyzer import (
                analyze_access_control_async,
            )

            access_control_available = True
        except ImportError:
            access_control_available = False

        access_control_analyzer_cls = None
        try:
            from src.analysis.automation.access_control import AccessControlAnalyzer as _Analyzer

            access_control_analyzer_cls = _Analyzer
            auto_ac_available = True
        except ImportError:
            auto_ac_available = False

        if not access_control_available and not auto_ac_available:
            logger.warning("Access control: no analyzer modules available, skipping")
            state_delta["module_metrics"]["access_control"] = {
                "status": "skipped",
                "reason": "no_analyzer_available",
                "duration_seconds": round(time.monotonic() - stage_started, 2),
            }
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="access_control",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=duration,
                metrics=state_delta["module_metrics"]["access_control"],
                state_delta=state_delta,
            )

        endpoints = _build_endpoint_list(ctx)

        if not endpoints:
            logger.info("No endpoints discovered, skipping access control testing")
            state_delta["module_metrics"]["access_control"] = {
                "status": "skipped",
                "reason": "no_endpoints",
                "duration_seconds": round(time.monotonic() - stage_started, 2),
            }
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="access_control",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=duration,
                metrics=state_delta["module_metrics"]["access_control"],
                state_delta=state_delta,
            )

        findings: list[dict[str, Any]] = []
        total_tests = len(endpoints)
        response_cache: Any = None
        try:
            response_cache = _build_access_control_cache(config)
        except (TypeError, ValueError, AttributeError) as exc:
            logger.warning("Access control cache initialization failed: %s", exc)

        last_heartbeat = time.monotonic()
        last_reported_processed = 0

        async def _emit_access_control_heartbeat(
            processed: int,
            total: int,
            current_url: str,
        ) -> None:
            nonlocal last_heartbeat, last_reported_processed
            now = time.monotonic()
            should_emit = (
                processed == total
                or processed <= 1
                or (processed - last_reported_processed) >= 10
                or (now - last_heartbeat) >= 15
            )
            if not should_emit:
                return
            last_heartbeat = now
            last_reported_processed = processed
            percent_complete = int((processed / max(1, total)) * 100)
            emit_progress(
                "access_control",
                f"Authorization checks {processed}/{total}",
                92,
                status="running",
                stage_status="running",
                stage_percent=percent_complete,
                targets_done=processed,
                targets_queued=max(0, total - processed),
                targets_scanning=1 if processed < total else 0,
                active_task_count=1,
                event_trigger="access_control_heartbeat",
                details={
                    "processed_endpoints": processed,
                    "total_endpoints": total,
                    "current_url": str(current_url or "")[:160],
                },
            )

        # Prefer the canonical async analyzer adapter.
        if access_control_available:
            findings = await analyze_access_control_async(
                endpoints,
                response_cache=response_cache,
                limit=max(1, len(endpoints)),
                progress_callback=_emit_access_control_heartbeat,
            )
        elif auto_ac_available and access_control_analyzer_cls is not None:
            analyzer = access_control_analyzer_cls(http_client=response_cache)
            enforcement_results = await analyzer.analyze_endpoints(
                endpoints,
                progress_callback=_emit_access_control_heartbeat,
            )
            findings = _findings_from_enforcement_results(enforcement_results)

        state_delta["reportable_findings"] = findings

        if not findings:
            logger.info("Access control: No authorization bypasses detected")
            state_delta["module_metrics"]["access_control"] = {
                "status": "ok",
                "duration_seconds": round(time.monotonic() - stage_started, 2),
                "total_tests": total_tests,
                "findings_count": 0,
            }
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="access_control",
                outcome=StageOutcome.COMPLETED,
                duration_seconds=duration,
                metrics=state_delta["module_metrics"]["access_control"],
                state_delta=state_delta,
            )

        state_delta["module_metrics"]["access_control"] = {
            "status": "ok",
            "duration_seconds": round(time.monotonic() - stage_started, 2),
            "total_tests": total_tests,
            "findings_count": len(findings),
        }

        high_sev = sum(
            1
            for f in findings
            if isinstance(f, dict) and str(f.get("severity", "")).lower() in ("critical", "high")
        )
        if high_sev:
            logger.warning(
                "Access control: %d high/critical bypass findings detected",
                high_sev,
            )

        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="access_control",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics=state_delta["module_metrics"]["access_control"],
            state_delta=state_delta,
        )

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'access_control' failed: %s", exc)
        ctx.mark_stage_failed("access_control", str(exc))
        state_delta["module_metrics"]["access_control"] = {
            "status": "error",
            "error": str(exc),
            "duration_seconds": round(time.monotonic() - stage_started, 2),
        }
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="access_control",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            reason="access_control_stage_exception",
            metrics=state_delta["module_metrics"]["access_control"],
            state_delta=state_delta,
        )


def _build_endpoint_list(ctx: PipelineContext) -> list[dict[str, Any]]:
    """Build endpoint list from pipeline context for testing."""
    endpoints: list[dict[str, Any]] = []

    response_lookup: dict[str, dict[str, Any]] = {}
    runtime_responses = (ctx.validation_runtime_inputs or {}).get("responses", [])
    if isinstance(runtime_responses, list):
        for response in runtime_responses:
            if not isinstance(response, dict):
                continue
            url = str(response.get("url", "")).strip()
            if _is_absolute_http_url(url):
                response_lookup[url] = response

    for url in ctx.urls:
        if not _is_absolute_http_url(url):
            continue
        endpoints.append(
            {
                "url": url,
                "method": "GET",
                "response": response_lookup.get(url, {}),
                "request_headers": {},
            }
        )

    for item in ctx.selected_priority_items:
        if isinstance(item, dict):
            url = item.get("url", "")
            if url and _is_absolute_http_url(url):
                response_payload = item.get("response", {})
                if not isinstance(response_payload, dict):
                    response_payload = response_lookup.get(str(url), {})
                endpoints.append(
                    {
                        "url": url,
                        "method": item.get("method", "GET"),
                        "response": response_payload,
                        "request_headers": item.get("headers", {}),
                    }
                )

    seen: set[str] = set()
    unique_endpoints: list[dict[str, Any]] = []
    for ep in endpoints:
        key = f"{ep['method']}:{ep['url']}"
        if key not in seen:
            seen.add(key)
            unique_endpoints.append(ep)

    return unique_endpoints

"""Execution wrappers and helpers for running active probes."""

from __future__ import annotations

import asyncio
import inspect
import os
from typing import Any, cast
from urllib.parse import parse_qsl, urlparse

from src.core.logging.trace_logging import get_pipeline_logger
from src.pipeline.runner_support import emit_progress

logger = get_pipeline_logger(__name__)


def _extract_jwt_candidates(url: str, cached_response: Any, *, probes: dict[str, Any]) -> list[str]:
    token_re = probes["jwt_token_regex"]
    if token_re is None:
        return []

    tokens: set[str] = set()
    for _, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        tokens.update(token_re.findall(str(value)))

    if isinstance(cached_response, dict):
        headers = cached_response.get("headers")
        if isinstance(headers, dict):
            for header_value in headers.values():
                tokens.update(token_re.findall(str(header_value)))
        body_text = str(cached_response.get("body_text") or cached_response.get("body") or "")
        if body_text:
            tokens.update(token_re.findall(body_text[:12000]))

    return sorted(tokens)


def _run_jwt_attack_suite(
    priority_items: list[dict[str, Any]],
    shared_response_cache: Any,
    max_targets: int = 2,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    try:
        import requests
    except (ImportError, TypeError, ValueError, AttributeError) as exc:
        logger.warning("Failed to import requests in JWT attack suite: %s", exc)
        return []

    findings: list[dict[str, Any]] = []
    tested = 0
    for item in priority_items:
        if tested >= max_targets:
            break

        url = str(item.get("url", "")).strip()
        if not url:
            continue

        cached_response = (
            shared_response_cache.get(url) if hasattr(shared_response_cache, "get") else None
        )
        tokens = _extract_jwt_candidates(url, cached_response, probes=probes)
        if not tokens:
            continue

        token = tokens[0]
        with requests.Session() as session:
            tested += 1
            result = probes["run_jwt_attack_suite"](token, url, session, config=None)
            if not isinstance(result, dict):
                continue

        vulnerable_attacks = int(result.get("vulnerable_attacks", 0) or 0)
        if vulnerable_attacks <= 0:
            continue

        vulnerable_list = result.get("vulnerable_list", [])
        issues = [f"jwt_attack_{name}" for name in vulnerable_list if str(name).strip()]
        if not issues:
            issues = ["jwt_attack_suite_vulnerable"]

        findings.append(
            {
                "url": url,
                "endpoint_key": url,
                "endpoint_base_key": url.split("?", 1)[0],
                "endpoint_type": "API",
                "issues": issues,
                "probe_type": "jwt_attack_suite",
                "severity": str(result.get("severity", "high") or "high"),
                "confidence": round(min(0.95, 0.6 + vulnerable_attacks * 0.05), 2),
                "evidence": {
                    "vulnerable_attacks": vulnerable_attacks,
                    "vulnerable_list": vulnerable_list,
                    "token_preview": str(result.get("token_preview", "")),
                },
            }
        )

    return findings


def _run_fuzzing_suggestion_probe(
    priority_urls: list[str],
    limit: int = 12,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    parameter_suggestions = probes["generate_payload_suggestions"](
        priority_urls,
        limit=limit,
    )
    header_suggestions = probes["generate_header_payloads"](
        priority_urls,
        limit=limit,
    )
    body_suggestions = probes["generate_body_payloads"](
        priority_urls,
        limit=limit,
    )

    per_url: dict[str, dict[str, Any]] = {}

    def _entry_for(url: str) -> dict[str, Any]:
        base = per_url.get(url)
        if isinstance(base, dict):
            return base
        record = {
            "url": url,
            "endpoint_key": url,
            "endpoint_base_key": url.split("?", 1)[0],
            "endpoint_type": "API",
            "issues": ["fuzzing_payload_candidates_generated"],
            "probe_type": "fuzzing_suggestions",
            "parameter_suggestion_count": 0,
            "header_suggestion_count": 0,
            "body_suggestion_count": 0,
            "sample_payloads": {},
        }
        per_url[url] = record
        return record

    if isinstance(parameter_suggestions, list):
        for item in parameter_suggestions:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            entry = _entry_for(url)
            suggestions = item.get("suggestions")
            if isinstance(suggestions, list):
                entry["parameter_suggestion_count"] += len(suggestions)
                if suggestions and "parameter" not in entry["sample_payloads"]:
                    entry["sample_payloads"]["parameter"] = suggestions[:3]

    if isinstance(header_suggestions, list):
        for item in header_suggestions:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            entry = _entry_for(url)
            suggestions = item.get("header_suggestions")
            if isinstance(suggestions, list):
                entry["header_suggestion_count"] += len(suggestions)
                if suggestions and "header" not in entry["sample_payloads"]:
                    entry["sample_payloads"]["header"] = suggestions[:3]

    if isinstance(body_suggestions, list):
        for item in body_suggestions:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            entry = _entry_for(url)
            suggestions = item.get("body_suggestions")
            if isinstance(suggestions, list):
                entry["body_suggestion_count"] += len(suggestions)
                if suggestions and "body" not in entry["sample_payloads"]:
                    entry["sample_payloads"]["body"] = suggestions[:3]

    findings: list[dict[str, Any]] = []
    for item in per_url.values():
        total = (
            int(item.get("parameter_suggestion_count", 0) or 0)
            + int(item.get("header_suggestion_count", 0) or 0)
            + int(item.get("body_suggestion_count", 0) or 0)
        )
        if total <= 0:
            continue
        item["confidence"] = 0.35
        item["severity"] = "info"
        item["evidence"] = {
            "total_suggestions": total,
            "parameter_suggestions": int(item.get("parameter_suggestion_count", 0) or 0),
            "header_suggestions": int(item.get("header_suggestion_count", 0) or 0),
            "body_suggestions": int(item.get("body_suggestion_count", 0) or 0),
        }
        findings.append(item)

    findings.sort(
        key=lambda finding: (
            -int((finding.get("evidence", {}) or {}).get("total_suggestions", 0)),
            str(finding.get("url", "")),
        )
    )
    return findings[:limit]


async def _try_probe(
    name: str,
    probe_fn: Any,
    *args: Any,
    timeout_seconds: float | None = None,
    error_accumulator: list[dict[str, Any]] | None = None,
    manifest: ActiveCheckManifest | None = None,
    **kwargs: Any,
) -> tuple[str, list[dict[str, Any]], bool]:
    """Run a probe, return (name, findings, success)."""
    import time

    from src.pipeline.services.instrumentation import StageEvent, event_bus, get_memory_usage

    start_time = time.perf_counter()
    start_mem = get_memory_usage()

    findings_list: list[dict[str, Any]] = []
    success = False
    termination_code = 0
    failure_reason = ""

    emit_progress(
        "active_scan",
        f"Starting active check {name}",
        91,
        check_id=name,
        sub_stage=name,
        telemetry_event_type="check.started",
        stage_status="running",
    )

    def _record_failure(reason: str, message: str) -> tuple[str, list[dict[str, Any]], bool]:
        nonlocal failure_reason, termination_code
        failure_reason = reason
        termination_code = 1
        logger.warning(message)
        emit_progress(
            "active_scan",
            message,
            91,
            check_id=name,
            sub_stage=name,
            telemetry_event_type="check.failed",
            stage_status="error",
            reason=reason,
            error=message,
        )
        if error_accumulator is not None:
            error_accumulator.append({"probe": name, "reason": reason, "message": message})
        return name, [], False

    try:
        try:
            from src.execution.active_manifest import get_active_manifest

            active_manifest = (manifest or get_active_manifest(name)).with_timeout(timeout_seconds)
        except KeyError:
            active_manifest = None

        if (
            active_manifest is not None
            and os.environ.get("ACTIVE_CHECK_ISOLATION", "process") != "off"
        ):
            from src.execution.active_manifest import ActiveCapability
            from src.execution.isolated import replace_unpicklable_response_caches, run_callable_isolated

            isolated_args = args
            isolated_kwargs = kwargs
            if ActiveCapability.RESPONSE_CACHE in active_manifest.required_capabilities:
                isolated_args = replace_unpicklable_response_caches(args)
                isolated_kwargs = replace_unpicklable_response_caches(kwargs)
            result = await asyncio.to_thread(
                run_callable_isolated,
                probe_fn,
                isolated_args,
                isolated_kwargs,
                active_manifest,
            )
            if result.reason == "serialization_error" and os.environ.get("PYTEST_CURRENT_TEST"):
                logger.debug("Falling back to in-process probe execution for pytest-local callable")
            elif result.reason == "serialization_error":
                return _record_failure(
                    "serialization_error",
                    f"Probe '{name}' could not enter isolated execution: {result.error}",
                )
            else:
                if not result.ok:
                    reason = result.reason or "error"
                    message = (
                        f"Probe '{name}' failed in isolated process: {result.error}"
                        if reason != "timeout"
                        else f"Probe '{name}' timed out after {active_manifest.budget.timeout_seconds}s"
                    )
                    return _record_failure(reason, message)

                findings = cast(
                    list[dict[str, Any]],
                    result.value
                    if isinstance(result.value, list)
                    else ([result.value] if result.value else []),
                )
                # Mark success *before* emitting the completion telemetry.
                # The previous ordering could leave ``success=False`` if
                # ``emit_progress`` raised, causing the ``finally`` block
                # to record a false failure after a successful probe.
                success = True
                findings_list = findings
                emit_progress(
                    "active_scan",
                    f"Completed active check {name} with {len(findings)} findings",
                    92,
                    check_id=name,
                    sub_stage=name,
                    telemetry_event_type="check.completed",
                    targets_done=len(findings),
                    stage_status="running",
                )
                return name, findings, True

        async def _execute_probe() -> object:
            if inspect.iscoroutinefunction(probe_fn):
                return await probe_fn(*args, **kwargs)

            result = await asyncio.to_thread(probe_fn, *args, **kwargs)
            if inspect.isawaitable(result):
                return await result
            return result

        try:
            if timeout_seconds is not None and timeout_seconds > 0:
                probe_result = await asyncio.wait_for(_execute_probe(), timeout=timeout_seconds)
            else:
                probe_result = await _execute_probe()
            findings = cast(
                list[dict[str, Any]],
                probe_result
                if isinstance(probe_result, list)
                else ([probe_result] if probe_result else []),
            )
            # Mark ``success`` *before* the success-only telemetry emit so
            # that even if ``emit_progress`` raises (extremely unlikely),
            # the ``finally`` block below records an accurate status.
            success = True
            findings_list = findings
            emit_progress(
                "active_scan",
                f"Completed active check {name} with {len(findings)} findings",
                92,
                check_id=name,
                sub_stage=name,
                telemetry_event_type="check.completed",
                targets_done=len(findings),
                stage_status="running",
            )
            return name, findings, True
        except TimeoutError:
            msg = f"Probe '{name}' timed out after {timeout_seconds}s"
            return _record_failure("timeout", msg)
        except Exception as exc:
            msg = f"Probe '{name}' failed: {exc}"
            return _record_failure("error", msg)
    finally:
        latency = time.perf_counter() - start_time
        mem_footprint = max(0.0, get_memory_usage() - start_mem)
        details = {
            "probe_name": name,
            "findings_count": len(findings_list),
            "success": success,
        }
        if failure_reason:
            details["reason"] = failure_reason
        event = StageEvent(
            stage_name=f"active_scan.probe.{name}",
            latency_seconds=latency,
            memory_footprint_mb=mem_footprint,
            termination_code=termination_code,
            details=details,
        )
        event_bus(event)


async def _run_workflow_fuzzer_probe(
    priority_items: list[dict[str, Any]],
    shared_response_cache: Any,
    limit: int = 8,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run the workflow/stateful fuzzer across priority URLs."""
    WorkflowFuzzerCls = probes.get("workflow_fuzzer_probe")
    if WorkflowFuzzerCls is None or WorkflowFuzzerCls is probes.get("run_auth_bypass_probes"):
        return []

    try:
        fuzzer = WorkflowFuzzerCls(max_steps=12)
        findings = await fuzzer.fuzz_workflow(
            priority_items,
            response_cache=shared_response_cache,
            limit=limit,
        )
        return findings if isinstance(findings, list) else []
    except Exception as exc:
        logger.debug("Workflow fuzzer probe failed: %s", exc)
        return []


async def _run_graphql_fuzzer_probe(
    priority_items: list[dict[str, Any]],
    shared_response_cache: Any,
    limit: int = 6,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run GraphQL introspection and mutation fuzzing on detected GraphQL endpoints."""
    run_campaign = probes.get("graphql_fuzzer_probe")
    if run_campaign is None or callable(getattr(run_campaign, "_stub", None)):
        return []

    findings: list[dict[str, Any]] = []
    tested = 0
    for item in priority_items:
        if tested >= limit:
            break
        url = str(item.get("url", "")).strip()
        if not url or "/graphql" not in url.lower():
            continue
        try:
            result = await run_campaign(url)
            if isinstance(result, list):
                findings.extend(result)
            tested += 1
        except Exception as exc:
            logger.debug("GraphQL fuzzer failed for %s: %s", url, exc)
    return findings


async def _run_framing_fuzzer_probe(
    priority_items: list[dict[str, Any]],
    shared_response_cache: Any,
    limit: int = 6,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run protocol-layer framing fuzzing (CL/TE smuggling, multipart, chunked, h2)."""
    run_campaign = probes.get("framing_fuzzer_probe")
    if run_campaign is None or callable(getattr(run_campaign, "_stub", None)):
        return []

    findings: list[dict[str, Any]] = []
    tested = 0
    for item in priority_items:
        if tested >= limit:
            break
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        try:
            result = await run_campaign(url)
            if isinstance(result, list):
                findings.extend(result)
            tested += 1
        except Exception as exc:
            logger.debug("Framing fuzzer failed for %s: %s", url, exc)
    return findings


async def _run_fuzzing_campaign_probe(
    priority_urls: list[str],
    limit: int = 6,
    *,
    probes: dict[str, Any],
) -> list[dict[str, Any]]:
    """Execute an active mutation parameter fuzzing campaign against priority URLs."""
    from src.fuzzing.orchestrator import FuzzingOrchestrator  # type: ignore[attr-defined]

    orchestrator = FuzzingOrchestrator(priority_urls)
    findings: list[dict[str, Any]] = []

    for url in priority_urls[:limit]:
        url = str(url).strip()
        if not url:
            continue
        try:
            logger.info("Fuzzer: Launching parameter mutation campaign on %s", url)
            campaign_findings = await orchestrator.run_fuzzing_campaign(url)
            findings.extend(campaign_findings)
        except Exception as exc:
            logger.warning("Fuzzer: Campaign failed on %s: %s", url, exc)

    return findings

"""Active scanning stage — wires existing probe modules into an orchestrated stage using parallel groups."""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context
from src.recon.common import normalize_url

logger = get_pipeline_logger(__name__)


def _is_absolute_http_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _normalize_scan_targets(targets: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in targets:
        value = normalize_url(str(raw or "").strip())
        if not value or not _is_absolute_http_url(value) or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _build_priority_items(targets: list[str]) -> list[dict[str, Any]]:
    return [{"url": target} for target in _normalize_scan_targets(targets)]


def _build_response_cache() -> Any:
    from src.analysis.passive.runtime import RequestScheduler, ResponseCache

    scheduler = RequestScheduler(rate_per_second=4.0, capacity=2.0, adaptive_mode=False)
    return ResponseCache(
        timeout_seconds=12,
        max_bytes=120_000,
        max_workers=6,
        scheduler=scheduler,
        persistent_cache_path=None,
        cache_ttl_hours=1,
    )


@functools.lru_cache(maxsize=1)
def _load_active_probe_functions() -> dict[str, Any]:
    from src.analysis.active.auth_bypass.analyzer import run_auth_bypass_probes
    from src.analysis.active.cloud_metadata import cloud_metadata_active_probe
    from src.analysis.active.coordinator import (
        cors_preflight_probe,
        csrf_active_probe,
        file_upload_active_probe,
        hpp_active_probe,
        idor_active_probe,
        oauth_flow_analyzer,
        options_method_probe,
        sqli_safe_probe,
        trace_method_probe,
        websocket_message_probe,
    )
    from src.analysis.active.graphql import graphql_active_probe
    from src.analysis.active.http_smuggling import http2_probe, http_smuggling_probe
    from src.analysis.active.injection.command_injection import command_injection_active_probe
    from src.analysis.active.injection.crlf.crlf_probe import crlf_injection_probe
    from src.analysis.active.injection.deserialization import deserialization_probe
    from src.analysis.active.injection.host_header import host_header_injection_probe
    from src.analysis.active.injection.jwt_manipulation import jwt_manipulation_probe
    from src.analysis.active.injection.ldap import ldap_injection_active_probe
    from src.analysis.active.injection.nosql import nosql_injection_probe
    from src.analysis.active.injection.open_redirect import open_redirect_active_probe
    from src.analysis.active.injection.path_traversal import path_traversal_active_probe
    from src.analysis.active.injection.proxy_ssrf import proxy_ssrf_probe
    from src.analysis.active.injection.ssrf import ssrf_active_probe
    from src.analysis.active.injection.ssti import ssti_active_probe
    from src.analysis.active.injection.xpath import xpath_injection_active_probe
    from src.analysis.active.injection.xss_reflect_probe import xss_reflect_probe
    from src.analysis.active.injection.xxe import xxe_active_probe
    from src.analysis.active.jwt_attacks import run_jwt_attack_suite
    from src.analysis.active.jwt_attacks._helpers import JWT_RE
    from src.analysis.intelligence.mutation_runtime import run_mutation_tests
    from src.analysis.json.active_probes import (
        filter_parameter_fuzzer,
        pagination_walker,
        parameter_dependency_tracker,
        state_transition_analyzer,
    )
    from src.analysis.response._core.response_analysis._diff_engine import response_diff_engine
    from src.fuzzing.payload_generator import generate_payload_suggestions
    from src.fuzzing.payload_generator_http import (
        generate_body_payloads,
        generate_header_payloads,
    )

    return {
        "run_auth_bypass_probes": run_auth_bypass_probes,
        "cloud_metadata_active_probe": cloud_metadata_active_probe,
        "cors_preflight_probe": cors_preflight_probe,
        "csrf_active_probe": csrf_active_probe,
        "command_injection_active_probe": command_injection_active_probe,
        "crlf_injection_probe": crlf_injection_probe,
        "deserialization_probe": deserialization_probe,
        "file_upload_active_probe": file_upload_active_probe,
        "filter_parameter_fuzzer": filter_parameter_fuzzer,
        "graphql_active_probe": graphql_active_probe,
        "host_header_injection_probe": host_header_injection_probe,
        "http2_probe": http2_probe,
        "http_smuggling_probe": http_smuggling_probe,
        "hpp_active_probe": hpp_active_probe,
        "idor_active_probe": idor_active_probe,
        "oauth_flow_analyzer": oauth_flow_analyzer,
        "ldap_injection_active_probe": ldap_injection_active_probe,
        "nosql_injection_probe": nosql_injection_probe,
        "open_redirect_active_probe": open_redirect_active_probe,
        "options_method_probe": options_method_probe,
        "pagination_walker": pagination_walker,
        "parameter_dependency_tracker": parameter_dependency_tracker,
        "path_traversal_active_probe": path_traversal_active_probe,
        "proxy_ssrf_probe": proxy_ssrf_probe,
        "generate_payload_suggestions": generate_payload_suggestions,
        "generate_header_payloads": generate_header_payloads,
        "generate_body_payloads": generate_body_payloads,
        "response_diff_engine": response_diff_engine,
        "run_jwt_attack_suite": run_jwt_attack_suite,
        "jwt_token_regex": JWT_RE,
        "sqli_safe_probe": sqli_safe_probe,
        "ssrf_active_probe": ssrf_active_probe,
        "ssti_active_probe": ssti_active_probe,
        "state_transition_analyzer": state_transition_analyzer,
        "trace_method_probe": trace_method_probe,
        "xss_reflect_probe": xss_reflect_probe,
        "xxe_active_probe": xxe_active_probe,
        "xpath_injection_active_probe": xpath_injection_active_probe,
        "websocket_message_probe": websocket_message_probe,
        "jwt_manipulation_probe": jwt_manipulation_probe,
        "run_mutation_tests": run_mutation_tests,
    }


async def _try_probe(
    name: str,
    probe_fn: Any,
    *args: Any,
    timeout_seconds: float | None = None,
    **kwargs: Any,
) -> tuple[str, list[dict[str, Any]], bool]:
    """Run a probe, return (name, findings, success)."""

    async def _execute_probe() -> object:
        if inspect.iscoroutinefunction(probe_fn):
            return await probe_fn(*args, **kwargs)

        result = await asyncio.to_thread(probe_fn, *args, **kwargs)
        if inspect.isawaitable(result):
            return await result
        return result

    try:
        if timeout_seconds is not None and timeout_seconds > 0:
            result = await asyncio.wait_for(_execute_probe(), timeout=timeout_seconds)
        else:
            result = await _execute_probe()
        findings = result if isinstance(result, list) else ([result] if result else [])
        return name, findings, True
    except TimeoutError:
        logger.warning("Probe '%s' timed out after %.1fs", name, float(timeout_seconds or 0.0))
        return name, [], False
    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.warning("Probe '%s' failed: %s", name, exc)
        return name, [], False


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
        from ._active_scan_adaptive import run_active_scanning_adaptive
        return await run_active_scanning_adaptive(args, config, ctx, stage_input=stage_input)

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
    except (TypeError, ValueError):
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

    def _run_probe(name: str, probe_fn: Any, *probe_args: Any) -> Any:
        return _try_probe(
            name,
            probe_fn,
            *probe_args,
            timeout_seconds=probe_timeout_seconds,
        )

    def _run_json_probe_suite(
        priority_urls: list[str],
        shared_response_cache: Any,
        limit: int = 24,
    ) -> list[dict[str, Any]]:
        if not priority_urls:
            return []

        findings: list[dict[str, Any]] = []
        probe_runs = [
            (
                "json_state_transition",
                probes["state_transition_analyzer"](
                    priority_urls,
                    shared_response_cache,
                    max(6, limit // 2),
                ),
            ),
            (
                "json_parameter_dependency",
                probes["parameter_dependency_tracker"](
                    priority_urls,
                    shared_response_cache,
                    max(6, limit // 2),
                ),
            ),
            (
                "json_pagination",
                probes["pagination_walker"](
                    priority_urls,
                    shared_response_cache,
                    max(6, limit // 2),
                ),
            ),
            (
                "json_filter_fuzz",
                probes["filter_parameter_fuzzer"](
                    priority_urls,
                    shared_response_cache,
                    max(6, limit // 2),
                ),
            ),
        ]

        for probe_name, probe_findings in probe_runs:
            if not isinstance(probe_findings, list):
                continue
            for finding in probe_findings:
                if len(findings) >= limit:
                    return findings
                item = dict(finding) if isinstance(finding, dict) else {"value": finding}
                item.setdefault("probe", probe_name)
                findings.append(item)
        return findings[:limit]

    def _run_http_smuggling_suite(
        priority_items: list[dict[str, Any]],
        shared_response_cache: Any,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        smuggling_findings = probes["http_smuggling_probe"](
            priority_items,
            shared_response_cache,
            limit=limit,
        )
        http2_findings = probes["http2_probe"](
            priority_items,
            shared_response_cache,
            limit=max(1, limit // 2),
        )
        combined = [
            *(
                smuggling_findings
                if isinstance(smuggling_findings, list)
                else ([smuggling_findings] if smuggling_findings else [])
            ),
            *(
                http2_findings
                if isinstance(http2_findings, list)
                else ([http2_findings] if http2_findings else [])
            ),
        ]
        combined.sort(
            key=lambda item: (
                -float(item.get("confidence", 0.0)) if isinstance(item, dict) else 0.0,
                str(item.get("url", "")) if isinstance(item, dict) else "",
            )
        )
        return [item for item in combined if isinstance(item, dict)][:limit]

    def _run_auth_bypass_suite(
        priority_items: list[dict[str, Any]],
        shared_response_cache: Any,
        limit: int = 12,
    ) -> list[dict[str, Any]]:
        suite_results = probes["run_auth_bypass_probes"](
            priority_items,
            shared_response_cache,
            config={
                "jwt_stripping_limit": max(4, limit // 2),
                "cookie_manipulation_limit": max(4, limit // 2),
                "auth_bypass_limit": max(4, limit // 2),
                "credential_stuffing_limit": max(2, limit // 4),
                "mfa_bypass_limit": max(2, limit // 4),
                "password_reset_abuse_limit": max(2, limit // 4),
            },
        )
        if not isinstance(suite_results, dict):
            return []

        flattened: list[dict[str, Any]] = []
        fallback_url = str(priority_items[0].get("url", "")).strip() if priority_items else ""
        for suite_name, suite_findings in suite_results.items():
            if not isinstance(suite_findings, list):
                continue
            for finding in suite_findings:
                if len(flattened) >= limit:
                    return flattened
                item = dict(finding) if isinstance(finding, dict) else {"value": finding}
                item.setdefault("probe_type", suite_name)
                issues = item.get("issues")
                if not isinstance(issues, list) or not issues:
                    item["issues"] = [f"{suite_name}_signal"]
                item.setdefault("confidence", 0.55)
                item.setdefault("severity", "medium")
                if not str(item.get("url", "")).strip() and fallback_url:
                    item["url"] = fallback_url
                flattened.append(item)
        return flattened[:limit]

    def _extract_jwt_candidates(url: str, cached_response: Any) -> list[str]:
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
    ) -> list[dict[str, Any]]:
        try:
            import requests
        except (ImportError, TypeError, ValueError, AttributeError):
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
            tokens = _extract_jwt_candidates(url, cached_response)
            if not tokens:
                continue

            token = tokens[0]
            session = requests.Session()
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

    emit_progress("active_scan", "Running CSRF and injection probes", 78, processed=1, total=6)
    results1 = await asyncio.gather(*group1, return_exceptions=True)

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

    # Group 2: IDOR, HPP, WebSocket, GraphQL (ranked_items + URL focused)
    group2 = [
        _run_probe("idor", probes["idor_active_probe"], ranked_priority_items, response_cache),
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
        _run_probe("auth_bypass", _run_auth_bypass_suite, url_priority_items, response_cache, 12),
        _run_probe("jwt_attacks", _run_jwt_attack_suite, url_priority_items, response_cache, 2),
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
        _run_probe("fuzzing_suggestions", _run_fuzzing_suggestion_probe, urls_l, 12),
        _run_probe("json", _run_json_probe_suite, urls_l, response_cache),
        _run_probe("response_diff", probes["response_diff_engine"], urls_l, response_cache),
    ]

    planned_probe_count = len(group1) + len(group2) + 5

    emit_progress(
        "active_scan",
        "Running GraphQL and cloud metadata probes",
        85,
        processed=probes_executed,
        total=planned_probe_count,
    )
    results2 = await asyncio.gather(*group2, return_exceptions=True)

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

    # Group 3: Host-focused probes
    group3 = [
        _run_probe("cors", probes["cors_preflight_probe"], host_priority_items, response_cache),
        _run_probe("trace", probes["trace_method_probe"], host_priority_items, response_cache),
        _run_probe("options", probes["options_method_probe"], host_priority_items, response_cache),
        _run_probe("cloud_metadata", probes["cloud_metadata_active_probe"], host_probe_targets),
        _run_probe(
            "http_smuggling", _run_http_smuggling_suite, host_priority_items, response_cache
        ),
    ]

    total_probe_count = len(group1) + len(group2) + len(group3)

    emit_progress(
        "active_scan",
        "Running mutation/fuzzing probes",
        88,
        processed=probes_executed,
        total=total_probe_count,
    )
    results3 = await asyncio.gather(*group3, return_exceptions=True)

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

    # Build state_delta with findings
    state_delta: dict[str, Any] = {
        "active_scan_findings": all_findings,
    }

    emit_progress(
        "active_scan",
        f"Active scan complete: {probes_succeeded}/{probes_executed} probes succeeded, {len(all_findings)} findings",
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

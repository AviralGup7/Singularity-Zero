"""Plugin runtime execution functions."""

import asyncio
import concurrent.futures
import inspect
import logging
from collections.abc import Callable, Iterable
from typing import Any, cast
from urllib.parse import urlparse

from src.analysis.passive.runtime import ResponseCache
from src.analysis.plugin_runtime_models import (
    AnalysisExecutionContext,
    AnalyzerBinding,
    DetectionGraphContext,
)
from src.core.utils import normalize_url

from ._bindings import ANALYZER_BINDINGS

logger = logging.getLogger(__name__)

_INPUT_KIND_KWARGS: dict[str, tuple[str, ...]] = {
    "responses_only": ("responses",),
    "urls_only": ("urls",),
    "urls_and_responses": ("urls", "responses"),
    "priority_urls_and_cache": ("priority_urls", "response_cache"),
    "priority_urls_only": ("priority_urls",),
    "ranked_items_and_cache": ("ranked_items", "response_cache"),
    "behavior_analysis": ("behavior_results",),
    "responses_and_bulk_items": ("responses", "bulk_items"),
    "header_targets_and_cache": ("header_targets", "response_cache"),
}


def _is_absolute_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return bool(parsed.scheme and parsed.netloc)


def _normalize_absolute_url(value: object) -> str:
    normalized = normalize_url(str(value or "").strip())
    return normalized if _is_absolute_url(normalized) else ""


def _sanitize_url_set(values: Iterable[str] | None) -> set[str]:
    cleaned: set[str] = set()
    for raw in values or []:
        normalized = _normalize_absolute_url(raw)
        if normalized:
            cleaned.add(normalized)
    return cleaned


def _sanitize_response_items(responses: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for item in responses or []:
        if not isinstance(item, dict):
            continue
        normalized_url = _normalize_absolute_url(item.get("url", ""))
        if not normalized_url:
            continue
        row = dict(item)
        row["url"] = normalized_url

        final_url = _normalize_absolute_url(row.get("final_url", ""))
        if final_url:
            row["final_url"] = final_url
        else:
            row.pop("final_url", None)

        requested_url = _normalize_absolute_url(row.get("requested_url", ""))
        if requested_url:
            row["requested_url"] = requested_url
        else:
            row.pop("requested_url", None)
        sanitized.append(row)
    return sanitized


def _sanitize_response_map(
    response_map: dict[str, dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    cleaned: dict[str, dict[str, Any]] = {}
    for key, value in (response_map or {}).items():
        if not isinstance(value, dict):
            continue
        normalized_key = _normalize_absolute_url(key)
        normalized_value_url = _normalize_absolute_url(value.get("url", ""))
        selected_key = normalized_key or normalized_value_url
        if not selected_key:
            continue
        row = dict(value)
        row["url"] = normalized_value_url or selected_key
        cleaned[selected_key] = row
    return cleaned


def _coerce_positive_int(value: object) -> int | None:
    try:
        parsed = int(cast(Any, value))
    except (TypeError, ValueError) as exc:
        logger.debug("Ignoring %s: %s", type(exc).__name__, exc)
        return None
    return parsed if parsed > 0 else None


def _binding_contract_issues(binding_key: str, binding: AnalyzerBinding) -> list[str]:
    issues: list[str] = []

    if binding.input_kind not in _INPUT_KIND_KWARGS:
        issues.append(f"unknown input kind '{binding.input_kind}'")

    runner = binding.runner
    if runner is None:
        return issues
    if not callable(runner):
        issues.append("runner is not callable")
        return issues

    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError) as exc:
        logger.debug("Ignoring %s: %s", type(exc).__name__, exc)
        return issues

    provided_kwargs = set(_INPUT_KIND_KWARGS.get(binding.input_kind, ()))
    if binding.extra_kwargs:
        provided_kwargs.update(binding.extra_kwargs.keys())
    if binding.context_attr:
        provided_kwargs.add(binding.context_attr)
    if binding.default_limit is not None or binding.limit_key:
        provided_kwargs.add("limit")

    accepts_var_kwargs = any(
        param.kind == inspect.Parameter.VAR_KEYWORD for param in signature.parameters.values()
    )
    if accepts_var_kwargs:
        return issues

    required_kwargs = {
        param.name
        for param in signature.parameters.values()
        if param.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
        and param.default is inspect._empty
    }
    missing = sorted(required_kwargs - provided_kwargs)
    if missing:
        issues.append(
            "missing required parameters from binding contract: "
            f"{', '.join(missing)} (runner={getattr(runner, '__name__', binding_key)})"
        )
    return issues


def _collect_binding_contract_issues() -> dict[str, list[str]]:
    issues_by_key: dict[str, list[str]] = {}
    for key, binding in ANALYZER_BINDINGS.items():
        issues = _binding_contract_issues(key, binding)
        if issues:
            issues_by_key[key] = issues
    return issues_by_key


def _resolve_limit(binding: AnalyzerBinding, context: AnalysisExecutionContext) -> int | None:
    configured_limit: object | None = None
    if binding.limit_key:
        configured_limit = context.analysis_config.get(binding.limit_key)
        parsed_configured = _coerce_positive_int(configured_limit)
        if parsed_configured is not None:
            return parsed_configured
    return _coerce_positive_int(binding.default_limit)


def _resolve_runner_result(runner_name: str, result: object) -> object:
    if not inspect.isawaitable(result):
        return result

    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    if running_loop is not None and running_loop.is_running():
        if inspect.iscoroutine(result):
            result.close()
        raise RuntimeError(
            f"Analyzer {runner_name} returned an awaitable inside a running event loop; "
            "register an explicit async execution path"
        )

    logger.warning(
        "Analyzer %s returned an awaitable; executing through asyncio runtime",
        runner_name,
    )
    return asyncio.run(cast(Any, result))


def _normalize_analyzer_result(analyzer_key: str, result: object) -> list[dict[str, Any]]:
    if not result:
        return []

    raw_items: list[object]
    if isinstance(result, list):
        raw_items = result
    else:
        raw_items = [result]

    findings: list[dict[str, Any]] = []
    for index, item in enumerate(raw_items):
        if not isinstance(item, dict):
            logger.warning(
                "Analyzer %s emitted a non-mapping finding at index %d; dropping entry",
                analyzer_key,
                index,
            )
            continue

        row = dict(item)
        if "url" in row:
            normalized_url = _normalize_absolute_url(row.get("url", ""))
            if not normalized_url:
                logger.warning(
                    "Analyzer %s emitted finding with non-absolute URL %r; dropping entry",
                    analyzer_key,
                    row.get("url"),
                )
                continue
            row["url"] = normalized_url
        findings.append(row)

    return findings


def prime_analysis_primitives(
    *,
    urls: set[str],
    responses: list[dict[str, Any]],
    priority_urls: list[str] | None = None,
    response_cache: ResponseCache | None = None,
    detection_graph: DetectionGraphContext | None = None,
    live_hosts: set[str] | None = None,
    analysis_config: dict[str, Any] | None = None,
    header_targets: list[str] | None = None,
    response_map: dict[str, dict[str, Any]] | None = None,
    ranked_priority_urls: list[dict[str, Any]] | None = None,
) -> AnalysisExecutionContext:
    """Build the analysis execution context from collected URLs and responses."""
    normalized_live_hosts = _sanitize_url_set(live_hosts or set())
    normalized_urls = _sanitize_url_set(urls)
    normalized_priority_urls = _sanitize_url_set(priority_urls or [])
    normalized_header_targets = sorted(_sanitize_url_set(header_targets or []))
    normalized_responses = _sanitize_response_items(responses)
    normalized_response_map = _sanitize_response_map(response_map)

    ctx = AnalysisExecutionContext(
        live_hosts=normalized_live_hosts,
        urls=normalized_urls,
        priority_urls=normalized_priority_urls,
        analysis_config=analysis_config or {},
        header_targets=normalized_header_targets,
        responses=normalized_responses,
        response_map=normalized_response_map,
        response_cache=response_cache,
        ranked_items=ranked_priority_urls or [],
        flow_items=[],
        bulk_items=[],
        payload_items=[],
        token_findings=[],
        csrf_findings=[],
        ssti_findings=[],
        upload_findings=[],
        business_logic_findings=[],
        rate_limit_findings=[],
        jwt_findings=[],
        smuggling_findings=[],
        ssrf_findings=[],
        idor_findings=[],
    )
    if detection_graph is not None:
        detection_graph.execution = ctx
    return ctx


def _resolve_input_kwargs(
    binding: AnalyzerBinding, context: AnalysisExecutionContext
) -> dict[str, object]:
    """Resolve kwargs for the given input_kind from the analysis context."""
    kind = binding.input_kind

    if kind == "responses_only":
        return {"responses": context.responses}
    if kind == "urls_only":
        return {"urls": context.urls}
    if kind == "urls_and_responses":
        return {"urls": context.urls, "responses": context.responses}
    if kind == "priority_urls_and_cache":
        return {
            "priority_urls": list(context.priority_urls),
            "response_cache": context.response_cache,
        }
    if kind == "priority_urls_only":
        return {"priority_urls": list(context.priority_urls)}
    if kind == "ranked_items_and_cache":
        return {
            "ranked_items": context.ranked_items,
            "response_cache": context.response_cache,
        }
    if kind == "behavior_analysis":
        return {"behavior_results": list(context.ranked_items)}
    if kind == "responses_and_bulk_items":
        return {"responses": context.responses, "bulk_items": context.bulk_items}
    if kind == "header_targets_and_cache":
        return {
            "header_targets": context.header_targets,
            "response_cache": context.response_cache,
        }

    return {}


def run_registered_analyzer(
    binding: AnalyzerBinding,
    context: AnalysisExecutionContext,
    timeout_seconds: int = 60,
    *,
    analyzer_key: str = "<unknown>",
) -> list[dict[str, Any]]:
    """Execute a single registered analyzer binding against the context."""
    runner = binding.runner
    if runner is None:
        return []

    kwargs: dict[str, object] = _resolve_input_kwargs(binding, context)

    if binding.extra_kwargs:
        kwargs.update(binding.extra_kwargs)

    if binding.context_attr:
        kwargs[binding.context_attr] = getattr(context, binding.context_attr)

    resolved_limit = _resolve_limit(binding, context)
    if resolved_limit is not None:
        kwargs.setdefault("limit", resolved_limit)

    runner_fn: Callable[..., list[dict[str, Any]]] = cast(
        Callable[..., list[dict[str, Any]]], runner
    )
    try:
        result = runner_fn(**kwargs)
        resolved_result = _resolve_runner_result(
            getattr(runner, "__name__", repr(runner)),
            result,
        )
        return _normalize_analyzer_result(analyzer_key, resolved_result)
    except Exception as exc:
        runner_name = getattr(runner, "__name__", repr(runner))
        if "timeout" in str(exc).lower():
            logger.warning("Analyzer %s timed out after %ds", runner_name, timeout_seconds)
        else:
            logger.warning("Analyzer %s failed: %s", runner_name, exc)
        return []


def run_analysis_plugins(
    context: AnalysisExecutionContext, max_workers: int = 10, timeout_seconds: int = 60
) -> dict[str, list[dict[str, Any]]]:
    """Run all registered analysis plugins and return results by key."""
    results: dict[str, list[dict[str, Any]]] = {}

    contract_issues = _collect_binding_contract_issues()
    for key, issues in contract_issues.items():
        for issue in issues:
            logger.warning("Analyzer binding '%s' skipped: %s", key, issue)
        results[key] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_key = {
            executor.submit(
                run_registered_analyzer,
                binding,
                context,
                timeout_seconds,
                analyzer_key=key,
            ): key
            for key, binding in ANALYZER_BINDINGS.items()
            if key not in contract_issues
        }
        for future in concurrent.futures.as_completed(future_to_key):
            key = future_to_key[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                logger.warning("Plugin %s failed: %s", key, exc)
                results[key] = []

    for key in ANALYZER_BINDINGS:
        results.setdefault(key, [])
    return results

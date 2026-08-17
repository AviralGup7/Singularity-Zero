"""Detection runtime facade delegating to the analysis layer.

Provides the analysis plugin execution system entry point.
Uses a class-based registry for testability and DI support.
"""

import logging
from collections.abc import Callable
from typing import Any

from src.core.contracts.plugin_types import AnalysisExecutionContext

logger = logging.getLogger(__name__)


class DetectionRuntime:
    """Registry for detection context and plugin execution handlers."""

    def __init__(
        self,
        prime_ctx: Callable[..., AnalysisExecutionContext] | None = None,
        run_plugins: Callable[[AnalysisExecutionContext], dict[str, list[dict[str, Any]]]]
        | None = None,
    ) -> None:
        self._prime_context_handler = prime_ctx
        self._run_plugins_handler = run_plugins

    def prime_context(self, **kwargs: Any) -> AnalysisExecutionContext:
        logger.info("Initializing detection context with parameters: %s", list(kwargs.keys()))
        if self._prime_context_handler is not None:
            context = self._prime_context_handler(**kwargs)
            logger.info("Detection context initialized successfully.")
            return context
        raise RuntimeError("No prime_context_handler registered in DetectionRuntime")

    def run_plugins(self, context: AnalysisExecutionContext) -> dict[str, list[dict[str, Any]]]:
        logger.info("Running all registered detection plugins.")
        if self._run_plugins_handler is not None:
            results = self._run_plugins_handler(context)
            logger.info(
                "Executed detection plugins. Returned results for %d plugins.", len(results)
            )
            return results
        raise RuntimeError("No run_plugins_handler registered in DetectionRuntime")


_default_runtime: DetectionRuntime | None = None


def _default_prime_context(**kwargs: Any) -> AnalysisExecutionContext:
    from src.core.contracts.plugin_types import AnalysisExecutionContext

    return AnalysisExecutionContext(
        live_hosts=set(kwargs.get("live_hosts", ())),
        urls=set(kwargs.get("urls", ())),
        priority_urls=set(kwargs.get("priority_urls", ())),
        analysis_config=dict(kwargs.get("analysis_config", {})),
        header_targets=list(kwargs.get("header_targets", ())),
        responses=list(kwargs.get("responses", ())),
        response_map=dict(kwargs.get("response_map", {})),
        response_cache=kwargs.get("response_cache", None),
        ranked_items=list(kwargs.get("ranked_items", ())),
        flow_items=list(kwargs.get("flow_items", ())),
        bulk_items=list(kwargs.get("bulk_items", ())),
        payload_items=list(kwargs.get("payload_items", ())),
        token_findings=list(kwargs.get("token_findings", ())),
        csrf_findings=list(kwargs.get("csrf_findings", ())),
        ssti_findings=list(kwargs.get("ssti_findings", ())),
        upload_findings=list(kwargs.get("upload_findings", ())),
        business_logic_findings=list(kwargs.get("business_logic_findings", ())),
        rate_limit_findings=list(kwargs.get("rate_limit_findings", ())),
        jwt_findings=list(kwargs.get("jwt_findings", ())),
        smuggling_findings=list(kwargs.get("smuggling_findings", ())),
        ssrf_findings=list(kwargs.get("ssrf_findings", ())),
        idor_findings=list(kwargs.get("idor_findings", ())),
    )


def get_runtime() -> DetectionRuntime:
    global _default_runtime
    if _default_runtime is None:
        try:
            from src.analysis.plugin_registration import (
                prime_detection_context_impl,
                run_detection_plugins_impl,
            )

            _default_runtime = DetectionRuntime(
                prime_ctx=prime_detection_context_impl,
                run_plugins=run_detection_plugins_impl,
            )
        except Exception:
            _default_runtime = DetectionRuntime(prime_ctx=_default_prime_context)
    elif _default_runtime._prime_context_handler is None:
        _default_runtime._prime_context_handler = _default_prime_context
    return _default_runtime


def set_runtime(runtime: DetectionRuntime) -> None:
    global _default_runtime
    _default_runtime = runtime


def register_detection_handlers(
    prime_ctx: Callable[..., AnalysisExecutionContext],
    run_plugins: Callable[[AnalysisExecutionContext], dict[str, list[dict[str, Any]]]],
) -> None:
    get_runtime()._prime_context_handler = prime_ctx
    get_runtime()._run_plugins_handler = run_plugins


def prime_detection_context(**kwargs: Any) -> AnalysisExecutionContext:
    return get_runtime().prime_context(**kwargs)


def run_detection_plugins(context: AnalysisExecutionContext) -> dict[str, list[dict[str, Any]]]:
    return get_runtime().run_plugins(context)

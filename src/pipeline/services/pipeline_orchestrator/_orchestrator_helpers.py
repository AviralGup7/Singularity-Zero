"""Shared helpers for orchestrator bootstrap and finalization."""

import logging
from collections.abc import Awaitable
from typing import Any

LEGACY_STAGE_ATTRS: dict[str, str] = {
    "subdomains": "run_subdomain_enumeration",
    "live_hosts": "run_live_hosts",
    "urls": "run_url_collection",
    "parameters": "run_parameter_extraction",
    "ranking": "run_priority_ranking",
    "passive_scan": "run_passive_scanning",
    "active_scan": "run_active_scanning",
    "nuclei": "run_nuclei_stage",
    "semgrep": "run_semgrep_stage",
    "access_control": "run_access_control_testing",
    "validation": "run_validation",
    "intelligence": "run_post_analysis_enrichments",
    "reporting": "run_reporting",
}

_STAGE_BASELINE_PROGRESS = {
    "subdomains": 12,
    "live_hosts": 30,
    "urls": 50,
    "parameters": 62,
    "ranking": 74,
    "priority": 78,
    "passive_scan": 86,
    "active_scan": 88,
    "nuclei": 90,
    "semgrep": 91,
    "access_control": 92,
    "validation": 94,
    "intelligence": 96,
    "reporting": 98,
}


def stage_baseline(stage_name: str, stage_order: list[str]) -> int:
    """Compute the baseline progress percentage for a given stage.

    Uses a predefined map of known stages for accurate percentages based on
    empirical pipeline timing data. Falls back to proportional calculation
    for unknown stages based on their position in the stage order.

    Args:
        stage_name: Name of the stage to look up.
        stage_order: Ordered list of all stage names in the pipeline.

    Returns:
        Estimated progress percentage (0-100) when the stage begins execution.
    """
    if stage_name in _STAGE_BASELINE_PROGRESS:
        return _STAGE_BASELINE_PROGRESS[stage_name]
    if stage_name in stage_order:
        index = stage_order.index(stage_name)
        return int(((index + 1) / max(1, len(stage_order))) * 100)
    return 0


def build_stage_methods_map(
    *,
    stage_order: list[str],
    module_globals: dict[str, Any],
    resolve_stage_runner_func: Any,
) -> dict[str, Any]:
    """Resolve concrete stage callables while preserving legacy monkeypatch seams."""
    stage_methods: dict[str, Any] = {}
    for stage_name in stage_order:
        legacy_attr = LEGACY_STAGE_ATTRS.get(stage_name, "")
        legacy_runner = module_globals.get(legacy_attr) if legacy_attr else None
        if callable(legacy_runner):
            stage_methods[stage_name] = legacy_runner
            continue
        try:
            stage_methods[stage_name] = resolve_stage_runner_func(stage_name)
        except KeyError:
            continue
    return stage_methods


async def finalize_run(
    *,
    event_bus: Any,
    exit_code: int,
    logger_obj: logging.Logger,
) -> int:
    """Drain async side effects and perform best-effort HTTP client cleanup."""
    try:
        flush_pending: Awaitable[Any] = event_bus.flush_pending(timeout=10.0)
        await flush_pending
    except Exception:
        logger_obj.debug("Failed to flush pending event handlers", exc_info=True)

    try:
        import gc

        import httpx

        leaked_clients = 0
        for obj in gc.get_objects():
            if not isinstance(obj, httpx.AsyncClient):
                continue
            if obj.is_closed:
                continue
            await obj.aclose()
            leaked_clients += 1
        if leaked_clients:
            logger_obj.debug("Closed %d leaked AsyncClient instance(s)", leaked_clients)
    except Exception:
        logger_obj.debug("Best-effort AsyncClient cleanup failed", exc_info=True)

    return exit_code

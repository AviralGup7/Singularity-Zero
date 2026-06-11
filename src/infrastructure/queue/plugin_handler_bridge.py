"""Bridge between the plugin registry and queue handler registry.

Automatically registers all pipeline plugin runners as queue job handlers,
so that enqueued ``TaskEnvelope`` instances are routed to the correct
plugin runner at dispatch time.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any, cast

from src.core.logging.trace_logging import get_pipeline_logger
from src.core.plugins import GLOBAL_PLUGIN_REGISTRY, list_plugins
from src.infrastructure.queue.models import Job

logger = get_pipeline_logger(__name__)

# Mapping from plugin kind → queue job type prefix
# The queue job type will be ``{kind}.{key}`` (e.g. ``scanner.nuclei``)
JOB_TYPE_SEPARATOR = "."

# Legacy short aliases so that jobs enqueued with the old plain
# type strings (e.g. ``"nuclei"``) still route correctly.
_LEGACY_JOB_TYPE_ALIASES: dict[str, str] = {
    "subdomains": "recon_provider.subdomains",
    "subdomain_enum": "recon_provider.subdomains",
    "live_hosts": "recon_provider.live_hosts",
    "port_probe": "recon_provider.live_hosts",
    "urls": "recon_provider.urls",
    "katana": "recon_provider.urls",
    "parameters": "recon_provider.parameters",
    "ranking": "recon_provider.ranking",
    "passive_scan": "scanner.passive_scan",
    "active_scan": "scanner.active_scan",
    "nuclei": "scanner.nuclei",
    "semgrep": "scanner.semgrep",
    "sca_scan": "scanner.sca_scan",
    "container_scan": "scanner.container_scan",
    "iac_scan": "scanner.iac_scan",
    "sbom_generate": "scanner.sbom_generate",
    "sbom_diff": "scanner.sbom_diff",
    "git_secret_scan": "scanner.git_secret_scan",
    "git_diff_crawl": "recon_provider.git_diff_crawl",
    "access_control": "validator.access_control",
    "validation": "validator.validation",
    "finding_revalidation": "validator.finding_revalidation",
    "intelligence": "enrichment_provider.intelligence",
    "threat_modeling": "enrichment_provider.threat_modeling",
    "reporting": "exporter.reporting",
    "sarif_export": "exporter.sarif_export",
    "report_distribution": "exporter.report_distribution",
    "subdomain_takeover": "recon_provider.subdomain_takeover",
    "hackerone_class": "ticket_creator.hackerone_class",
    "bugcrowd_class": "ticket_creator.bugcrowd_class",
    "jira_class": "ticket_creator.jira_class",
}


def normalize_job_type(job_type: str) -> str:
    """Resolve a job type string to its canonical ``kind.key`` form.

    If *job_type* is already in ``kind.key`` form, return it unchanged.
    Otherwise look it up in the legacy alias table.
    """
    if JOB_TYPE_SEPARATOR in job_type:
        return job_type
    return _LEGACY_JOB_TYPE_ALIASES.get(job_type, job_type)


def _make_plugin_handler(kind: str, key: str) -> Callable[[Job], Any]:
    """Create a queue handler that delegates to the plugin registry."""
    canonical = f"{kind}{JOB_TYPE_SEPARATOR}{key}"

    def handler(job: Job) -> Any:
        runner = GLOBAL_PLUGIN_REGISTRY.resolve(kind, key)
        envelope = job.as_task_envelope()
        if asyncio.iscoroutinefunction(runner):
            return runner(envelope)
        return runner(envelope)

    handler.__name__ = f"queue_handler({canonical})"
    handler.__qualname__ = f"queue_handler({canonical})"
    return handler


def register_all_plugin_handlers(queue: Any) -> int:
    """Register every known plugin runner as a queue handler.

    Returns the number of handlers registered.
    """
    count = 0
    for kind in (
        "recon_provider",
        "scanner",
        "validator",
        "enrichment_provider",
        "exporter",
        "bug_bounty",
        "ticket_creator",
    ):
        for registration in list_plugins(kind):
            canonical = f"{kind}{JOB_TYPE_SEPARATOR}{registration.key}"
            handler = _make_plugin_handler(kind, registration.key)
            queue.register_handler(canonical, handler)
            count += 1
            logger.debug("Registered queue handler: %s", canonical)

            # Also register the bare key as a legacy alias
            if registration.key not in queue._handlers:
                queue.register_handler(registration.key, handler)

    logger.info("Registered %d plugin handlers as queue handlers", count)
    return count


def resolve_handler_for_job_type(queue: Any, job_type: str) -> Callable[[Job], Any] | None:
    """Look up a handler for *job_type*, trying canonical then legacy forms."""
    canonical = normalize_job_type(job_type)
    handler = queue.get_handler(canonical)
    if handler is not None:
        return cast("Callable[[Job], Any] | None", handler)
    handler = queue.get_handler(job_type)
    if handler is not None:
        return cast("Callable[[Job], Any] | None", handler)
    return None

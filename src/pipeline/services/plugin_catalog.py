"""Plugin registration hot-path for the Neural-Mesh pipeline orchestrator.

The legacy plugin catalog mirrors the built-in tool runners behind the
``kind / name`` tuple key used by :func:`resolve_stage_runner`.  The
same catalog now bridges to the new
:class:`~src.pipeline.stage_registry.StageRegistry`: after the
default runners are registered every :class:`~src.pipeline.stage_registry.StageNodeDefinition`
known to the global registry is made visible through
:func:`list_registered_stage_definitions` and
:func:`resolve_stage_definition`.

External modules don't need to call ``register_stage_definition``
explicitly at runtime — ``_register_defaults`` already imports the
built-in stages and then refreshes the dynamic plugin loader.  Third-
party plugins that need to insert new graph nodes should call
:func:`src.pipeline.stage_registry.register_stage_definition` at
import time, before the first call to
:func:`~pipeline.services.pipeline_orchestrator.graph_builder.build_pipeline_graph`.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any, cast

from src.core.plugins import list_plugins, register_plugin, resolve_plugin
from src.core.plugins.loader import refresh_dynamic_plugins
from src.pipeline.stage_registry import (
    StageNodeDefinition,
    _global_stage_registry,
)
from src.pipeline.stage_registry import (
    resolve_stage_definition as _resolve_stage_definition,
)

RECON_PROVIDER = "recon_provider"
SCANNER = "scanner"
VALIDATOR = "validator"
EXPORTER = "exporter"
ENRICHMENT_PROVIDER = "enrichment_provider"
TICKET_CREATOR = "ticket_creator"
BUG_BOUNTY = "bug_bounty"

import time

_DEFAULTS_REGISTERED = False
_LAST_REFRESH_TIME = 0.0
REFRESH_THROTTLE_SECONDS = 5.0

# Lazy stage registration map: (kind, name) -> (module_path, attr_name)
# Stages are only imported when actually resolved, not at catalog init time.
_LAZY_STAGE_REGISTRY: dict[tuple[str, str], tuple[str, str]] = {
    (RECON_PROVIDER, "subdomains"): (
        ".pipeline_orchestrator.stages.recon",
        "run_subdomain_enumeration",
    ),
    (RECON_PROVIDER, "live_hosts"): (
        ".pipeline_orchestrator.stages.recon",
        "run_live_hosts",
    ),
    (RECON_PROVIDER, "urls"): (
        ".pipeline_orchestrator.stages.recon",
        "run_url_collection",
    ),
    (RECON_PROVIDER, "parameters"): (
        ".pipeline_orchestrator.stages.recon",
        "run_parameter_extraction",
    ),
    (RECON_PROVIDER, "ranking"): (
        ".pipeline_orchestrator.stages.recon",
        "run_priority_ranking",
    ),
    (RECON_PROVIDER, "subdomain_takeover"): (
        ".pipeline_orchestrator.stages.adaptive_extra",
        "run_subdomain_takeover",
    ),
    (RECON_PROVIDER, "git_diff_crawl"): (
        ".pipeline_orchestrator.stages.git_diff_crawl",
        "run_git_diff_crawl",
    ),
    (SCANNER, "passive_scan"): (
        ".pipeline_orchestrator.stages.analysis",
        "run_passive_scanning",
    ),
    (SCANNER, "active_scan"): (
        ".pipeline_orchestrator.stages.active_scan",
        "run_active_scanning",
    ),
    (SCANNER, "nuclei"): (
        ".pipeline_orchestrator.stages.nuclei",
        "run_nuclei_stage",
    ),
    (SCANNER, "semgrep"): (
        ".pipeline_orchestrator.stages.semgrep",
        "run_semgrep_stage",
    ),
    (SCANNER, "sca_scan"): (
        ".pipeline_orchestrator.stages.sca_scan",
        "run_sca_scan_stage",
    ),
    (SCANNER, "container_scan"): (
        ".pipeline_orchestrator.stages.container_scan",
        "run_container_scan_stage",
    ),
    (SCANNER, "iac_scan"): (
        ".pipeline_orchestrator.stages.iac_scan",
        "run_iac_scan_stage",
    ),
    (SCANNER, "sbom_generate"): (
        ".pipeline_orchestrator.stages.sbom_generate",
        "run_sbom_generate_stage",
    ),
    (SCANNER, "sbom_diff"): (
        ".pipeline_orchestrator.stages.sbom_diff",
        "run_sbom_diff_stage",
    ),
    (SCANNER, "git_secret_scan"): (
        ".pipeline_orchestrator.stages.git_secret_scan",
        "run_git_secret_scan_stage",
    ),
    (VALIDATOR, "access_control"): (
        ".pipeline_orchestrator.stages.access_control",
        "run_access_control_testing",
    ),
    (VALIDATOR, "validation"): (
        ".pipeline_orchestrator.stages.validation",
        "run_validation",
    ),
    (VALIDATOR, "finding_revalidation"): (
        ".pipeline_orchestrator.stages.finding_revalidation",
        "run_finding_revalidation",
    ),
    (ENRICHMENT_PROVIDER, "intelligence"): (
        ".pipeline_orchestrator.stages.enrichment",
        "run_post_analysis_enrichments",
    ),
    (ENRICHMENT_PROVIDER, "threat_modeling"): (
        ".pipeline_orchestrator.stages.adaptive_extra",
        "run_threat_modeling",
    ),
    (EXPORTER, "reporting"): (
        ".pipeline_orchestrator.stages.reporting",
        "run_reporting",
    ),
    (EXPORTER, "sarif_export"): (
        ".pipeline_orchestrator.stages.sarif_export",
        "run_sarif_export",
    ),
    (EXPORTER, "report_distribution"): (
        ".pipeline_orchestrator.stages.report_distribution",
        "run_report_distribution",
    ),
}


def _throttled_refresh() -> None:
    global _LAST_REFRESH_TIME
    now = time.time()
    if now - _LAST_REFRESH_TIME >= REFRESH_THROTTLE_SECONDS:
        refresh_dynamic_plugins()
        _LAST_REFRESH_TIME = now


def register_stage_definitions() -> None:
    _throttled_refresh()


def _make_lazy_loader(module_path: str, attr_name: str) -> Callable[..., Any]:
    """Return a callable that lazily imports and invokes the real stage runner."""
    _resolved: list[Callable[..., Any] | None] = [None]

    def _lazy_runner(*args: Any, **kwargs: Any) -> Any:
        if _resolved[0] is None:
            mod = importlib.import_module(module_path, package="src.pipeline.services")
            _resolved[0] = getattr(mod, attr_name)
        return _resolved[0](*args, **kwargs)

    _lazy_runner.__name__ = attr_name
    _lazy_runner.__qualname__ = attr_name
    return _lazy_runner


def _register_defaults() -> None:
    global _DEFAULTS_REGISTERED
    if _DEFAULTS_REGISTERED:
        return

    # Register lazy stage runners — the actual module imports happen
    # only when the stage is first resolved and called.
    for (kind, name), (module_path, attr_name) in _LAZY_STAGE_REGISTRY.items():
        register_plugin(kind, name)(_make_lazy_loader(module_path, attr_name))

    from src.analysis.automation.ticket_creators import (
        BugcrowdTicketCreator,
        HackerOneTicketCreator,
        JiraTicketCreator,
        register_default_ticket_creators,
    )

    register_default_ticket_creators()
    register_plugin(TICKET_CREATOR, "hackerone_class")(HackerOneTicketCreator)
    register_plugin(TICKET_CREATOR, "bugcrowd_class")(BugcrowdTicketCreator)
    register_plugin(TICKET_CREATOR, "jira_class")(JiraTicketCreator)

    import src.analysis.behavior.api_security  # noqa: F401
    import src.analysis.behavior.dns_security  # noqa: F401
    import src.analysis.intelligence.aggregator  # noqa: F401
    import src.analysis.intelligence.cvss_scoring  # noqa: F401
    import src.recon.subdomains  # noqa: F401
    import src.recon.urls  # noqa: F401
    import src.reporting.pipeline  # noqa: F401

    register_stage_definitions()
    _DEFAULTS_REGISTERED = True


def resolve_stage_runner(stage_name: str) -> Callable[..., Any]:
    _register_defaults()
    _throttled_refresh()
    normalized = stage_name.strip().lower()
    for kind in (
        RECON_PROVIDER,
        SCANNER,
        VALIDATOR,
        ENRICHMENT_PROVIDER,
        EXPORTER,
        BUG_BOUNTY,
        TICKET_CREATOR,
    ):
        try:
            return cast(Callable[..., Any], resolve_plugin(kind, normalized))
        except KeyError:
            continue
    raise KeyError(f"No stage runner plugin registered for '{stage_name}'")


def list_registered_stage_runners() -> dict[str, tuple[str, ...]]:
    _register_defaults()
    _throttled_refresh()
    return {
        RECON_PROVIDER: tuple(reg.key for reg in list_plugins(RECON_PROVIDER)),
        SCANNER: tuple(reg.key for reg in list_plugins(SCANNER)),
        VALIDATOR: tuple(reg.key for reg in list_plugins(VALIDATOR)),
        ENRICHMENT_PROVIDER: tuple(reg.key for reg in list_plugins(ENRICHMENT_PROVIDER)),
        EXPORTER: tuple(reg.key for reg in list_plugins(EXPORTER)),
        TICKET_CREATOR: tuple(reg.key for reg in list_plugins(TICKET_CREATOR)),
    }


def list_registered_stage_definitions() -> list[StageNodeDefinition]:
    return list(_global_stage_registry.get_all())


def resolve_stage_definition(name: str) -> StageNodeDefinition | None:
    return _resolve_stage_definition(name)

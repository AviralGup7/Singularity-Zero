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

from collections.abc import Callable
from typing import Any, cast

from src.core.plugins import list_plugins, register_plugin, resolve_plugin
from src.core.plugins.loader import refresh_dynamic_plugins
from src.pipeline.stage_registry import (
    StageNodeDefinition,
    _global_stage_registry,
    list_registered_stage_definitions,
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


def _throttled_refresh() -> None:
    global _LAST_REFRESH_TIME
    now = time.time()
    if now - _LAST_REFRESH_TIME >= REFRESH_THROTTLE_SECONDS:
        refresh_dynamic_plugins()
        _LAST_REFRESH_TIME = now


def register_stage_definitions() -> None:
    _throttled_refresh()


def _register_defaults() -> None:
    global _DEFAULTS_REGISTERED
    if _DEFAULTS_REGISTERED:
        return

    from src.pipeline.services.pipeline_orchestrator.stages.access_control import (
        run_access_control_testing,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.active_scan import run_active_scanning
    from src.pipeline.services.pipeline_orchestrator.stages.adaptive_extra import (
        run_subdomain_takeover,
        run_threat_modeling,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.analysis import run_passive_scanning
    from src.pipeline.services.pipeline_orchestrator.stages.enrichment import (
        run_post_analysis_enrichments,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.finding_revalidation import (
        run_finding_revalidation,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.git_diff_crawl import (
        run_git_diff_crawl,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.nuclei import run_nuclei_stage
    from src.pipeline.services.pipeline_orchestrator.stages.recon import (
        run_live_hosts,
        run_parameter_extraction,
        run_priority_ranking,
        run_subdomain_enumeration,
        run_url_collection,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.report_distribution import (
        run_report_distribution,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.reporting import run_reporting
    from src.pipeline.services.pipeline_orchestrator.stages.sarif_export import run_sarif_export
    from src.pipeline.services.pipeline_orchestrator.stages.semgrep import run_semgrep_stage
    from src.pipeline.services.pipeline_orchestrator.stages.validation import run_validation
    from src.pipeline.services.pipeline_orchestrator.stages.sca_scan import run_sca_scan_stage
    from src.pipeline.services.pipeline_orchestrator.stages.container_scan import run_container_scan_stage
    from src.pipeline.services.pipeline_orchestrator.stages.iac_scan import run_iac_scan_stage
    from src.pipeline.services.pipeline_orchestrator.stages.sbom_generate import run_sbom_generate_stage
    from src.pipeline.services.pipeline_orchestrator.stages.sbom_diff import run_sbom_diff_stage
    from src.pipeline.services.pipeline_orchestrator.stages.git_secret_scan import run_git_secret_scan_stage

    register_plugin(RECON_PROVIDER, "subdomains")(run_subdomain_enumeration)
    register_plugin(RECON_PROVIDER, "live_hosts")(run_live_hosts)
    register_plugin(RECON_PROVIDER, "urls")(run_url_collection)
    register_plugin(RECON_PROVIDER, "parameters")(run_parameter_extraction)
    register_plugin(RECON_PROVIDER, "ranking")(run_priority_ranking)
    register_plugin(RECON_PROVIDER, "subdomain_takeover")(run_subdomain_takeover)
    register_plugin(RECON_PROVIDER, "git_diff_crawl")(run_git_diff_crawl)

    register_plugin(SCANNER, "passive_scan")(run_passive_scanning)
    register_plugin(SCANNER, "active_scan")(run_active_scanning)
    register_plugin(SCANNER, "nuclei")(run_nuclei_stage)
    register_plugin(SCANNER, "semgrep")(run_semgrep_stage)
    register_plugin(SCANNER, "sca_scan")(run_sca_scan_stage)
    register_plugin(SCANNER, "container_scan")(run_container_scan_stage)
    register_plugin(SCANNER, "iac_scan")(run_iac_scan_stage)
    register_plugin(SCANNER, "sbom_generate")(run_sbom_generate_stage)
    register_plugin(SCANNER, "sbom_diff")(run_sbom_diff_stage)
    register_plugin(SCANNER, "git_secret_scan")(run_git_secret_scan_stage)

    register_plugin(VALIDATOR, "access_control")(run_access_control_testing)
    register_plugin(VALIDATOR, "validation")(run_validation)
    register_plugin(VALIDATOR, "finding_revalidation")(run_finding_revalidation)

    register_plugin(ENRICHMENT_PROVIDER, "intelligence")(run_post_analysis_enrichments)
    register_plugin(ENRICHMENT_PROVIDER, "threat_modeling")(run_threat_modeling)
    register_plugin(EXPORTER, "reporting")(run_reporting)
    register_plugin(EXPORTER, "sarif_export")(run_sarif_export)
    register_plugin(EXPORTER, "report_distribution")(run_report_distribution)

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
    import src.execution.validators.engine._validators  # noqa: F401
    import src.recon.subdomains  # noqa: F401
    import src.recon.urls  # noqa: F401
    import src.reporting.pipeline  # noqa: F401

    register_stage_definitions()
    _DEFAULTS_REGISTERED = True


def resolve_stage_runner(stage_name: str) -> Callable[..., Any]:
    _register_defaults()
    _throttled_refresh()
    normalized = stage_name.strip().lower()
    for kind in (RECON_PROVIDER, SCANNER, VALIDATOR, ENRICHMENT_PROVIDER, EXPORTER, BUG_BOUNTY, TICKET_CREATOR):
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

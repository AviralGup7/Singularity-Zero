from __future__ import annotations

from collections.abc import Callable
from typing import Any

from src.core.plugins import list_plugins, register_plugin, resolve_plugin

RECON_PROVIDER = "recon_provider"
SCANNER = "scanner"
VALIDATOR = "validator"
EXPORTER = "exporter"
ENRICHMENT_PROVIDER = "enrichment_provider"

_DEFAULTS_REGISTERED = False


def _register_defaults() -> None:
    global _DEFAULTS_REGISTERED
    if _DEFAULTS_REGISTERED:
        return

    from src.pipeline.services.pipeline_orchestrator.stages.access_control import (
        run_access_control_testing,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.active_scan import run_active_scanning
    from src.pipeline.services.pipeline_orchestrator.stages.analysis import run_passive_scanning
    from src.pipeline.services.pipeline_orchestrator.stages.enrichment import (
        run_post_analysis_enrichments,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.nuclei import run_nuclei_stage
    from src.pipeline.services.pipeline_orchestrator.stages.recon import (
        run_live_hosts,
        run_parameter_extraction,
        run_priority_ranking,
        run_subdomain_enumeration,
        run_url_collection,
    )
    from src.pipeline.services.pipeline_orchestrator.stages.reporting import run_reporting
    from src.pipeline.services.pipeline_orchestrator.stages.semgrep import run_semgrep_stage
    from src.pipeline.services.pipeline_orchestrator.stages.validation import run_validation

    register_plugin(RECON_PROVIDER, "subdomains")(run_subdomain_enumeration)
    register_plugin(RECON_PROVIDER, "live_hosts")(run_live_hosts)
    register_plugin(RECON_PROVIDER, "urls")(run_url_collection)
    register_plugin(RECON_PROVIDER, "parameters")(run_parameter_extraction)
    register_plugin(RECON_PROVIDER, "ranking")(run_priority_ranking)

    register_plugin(SCANNER, "passive_scan")(run_passive_scanning)
    register_plugin(SCANNER, "active_scan")(run_active_scanning)
    register_plugin(SCANNER, "nuclei")(run_nuclei_stage)
    register_plugin(SCANNER, "semgrep")(run_semgrep_stage)

    register_plugin(VALIDATOR, "access_control")(run_access_control_testing)
    register_plugin(VALIDATOR, "validation")(run_validation)

    register_plugin(ENRICHMENT_PROVIDER, "intelligence")(run_post_analysis_enrichments)
    register_plugin(EXPORTER, "reporting")(run_reporting)

    # Trigger internal plugin registrations via module imports
    import src.analysis.behavior.api_security  # noqa: F401
    import src.analysis.behavior.dns_security  # noqa: F401
    import src.analysis.intelligence.aggregator  # noqa: F401
    import src.analysis.intelligence.cvss_scoring  # noqa: F401
    import src.execution.validators.engine._validators  # noqa: F401
    import src.recon.subdomains  # noqa: F401
    import src.recon.urls  # noqa: F401
    import src.reporting.pipeline  # noqa: F401

    _DEFAULTS_REGISTERED = True


def resolve_stage_runner(stage_name: str) -> Callable[..., Any]:
    _register_defaults()
    normalized = stage_name.strip().lower()
    for kind in (RECON_PROVIDER, SCANNER, VALIDATOR, ENRICHMENT_PROVIDER, EXPORTER):
        try:
            return resolve_plugin(kind, normalized)
        except KeyError:
            continue
    raise KeyError(f"No stage runner plugin registered for '{stage_name}'")


def list_registered_stage_runners() -> dict[str, tuple[str, ...]]:
    _register_defaults()
    return {
        RECON_PROVIDER: tuple(reg.key for reg in list_plugins(RECON_PROVIDER)),
        SCANNER: tuple(reg.key for reg in list_plugins(SCANNER)),
        VALIDATOR: tuple(reg.key for reg in list_plugins(VALIDATOR)),
        ENRICHMENT_PROVIDER: tuple(reg.key for reg in list_plugins(ENRICHMENT_PROVIDER)),
        EXPORTER: tuple(reg.key for reg in list_plugins(EXPORTER)),
    }

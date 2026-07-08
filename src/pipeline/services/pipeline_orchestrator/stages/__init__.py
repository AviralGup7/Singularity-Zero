"""Stage modules for the pipeline orchestrator.

Stage imports are deferred via ``__getattr__`` so that importing this
package does not eagerly pull in all stage modules (and their heavy
transitive dependencies).  Individual stage functions are loaded on
first attribute access.
"""

from __future__ import annotations

from typing import Any

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "run_active_scanning": (".active_scan", "run_active_scanning"),
    "run_passive_scanning": (".analysis", "run_passive_scanning"),
    "run_ci_export": (".ci_export", "run_ci_export"),
    "run_dedup_stage": (".dedup_stage", "run_dedup_stage"),
    "run_post_analysis_enrichments": (".enrichment", "run_post_analysis_enrichments"),
    "run_git_diff_crawl": (".git_diff_crawl", "run_git_diff_crawl"),
    "run_nuclei_stage": (".nuclei", "run_nuclei_stage"),
    "run_live_hosts": (".recon", "run_live_hosts"),
    "run_parameter_extraction": (".recon", "run_parameter_extraction"),
    "run_priority_ranking": (".recon", "run_priority_ranking"),
    "run_subdomain_enumeration": (".recon", "run_subdomain_enumeration"),
    "run_url_collection": (".recon", "run_url_collection"),
    "run_waf_detection": (".recon", "run_waf_detection"),
    "run_reporting": (".reporting", "run_reporting"),
    "run_sarif_export": (".sarif_export", "run_sarif_export"),
    "run_scope_stage": (".scope_stage", "run_scope_stage"),
    "run_semgrep_stage": (".semgrep", "run_semgrep_stage"),
    "run_validation": (".validation", "run_validation"),
}

__all__ = list(_LAZY_IMPORTS)


def __getattr__(name: str) -> Any:
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path, package=__name__)
        value = getattr(module, attr_name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""Constants and configuration for pipeline orchestration."""

__all__ = [
    "PIPELINE_STAGES",
    "STAGE_ORDER",
    "STAGE_TIMEOUTS",
    "STAGE_DEPS",
    "DEFAULT_ITERATION_LIMIT",
    "DEFAULT_TIMEOUT_SECONDS",
    "PARALLEL_STAGE_GROUPS",
]

PIPELINE_STAGES = {
    "subdomains": "Subdomain enumeration",
    "live_hosts": "Live host probing",
    "waf": "WAF/CDN detection",
    "urls": "URL collection",
    "parameters": "Parameter extraction",
    "ranking": "Priority ranking",
    "passive_scan": "Passive analysis",
    "active_scan": "Active probing",
    "semgrep": "Static analysis (Semgrep)",
    "validation": "Validation runtime",
    "intelligence": "Intelligence merge",
    "access_control": "Authorization bypass detection",
    "reporting": "Report generation",
}

STAGE_TIMEOUTS = {
    "subdomains": 600,
    "live_hosts": 900,
    "waf": 120,
    "urls": 900,
    "parameters": 120,
    "ranking": 60,
    "passive_scan": 300,
    "active_scan": 900,
    "semgrep": 600,
    "validation": 300,
    "intelligence": 180,
    "access_control": 600,
    "reporting": 300,
    "nuclei": 600,
}

# Stage timeout reasoning:
# subdomains (600s): DNS enumeration with retries for large scopes
# live_hosts (900s): HTTP probing with batch concurrency for 1000s of hosts
# waf (120s): WAF/CDN active fingerprinting probes
# urls (900s): URL collection from multiple sources with rate limiting
# parameters (120s): Fast parameter extraction from collected URLs
# ranking (60s): Lightweight scoring and prioritization
# passive_scan (300s): Passive analysis with external API lookups
# active_scan (900s): Active probing with multiple tool categories
# semgrep (600s): Static analysis with multiple rule sets
# validation (300s): Runtime validation of findings
# intelligence (180s): Threat intel feed aggregation and correlation
# access_control (600s): Authorization bypass detection across auth flows
# reporting (300s): Report generation and export
# nuclei (600s): Nuclei vulnerability scanning with custom templates

STAGE_ORDER = [
    "subdomains",
    "live_hosts",
    "waf",
    "urls",
    "parameters",
    "ranking",
    "passive_scan",
    "active_scan",
    "semgrep",
    "nuclei",
    "access_control",
    "validation",
    "intelligence",
    "reporting",
]

DEFAULT_ITERATION_LIMIT = 3
DEFAULT_TIMEOUT_SECONDS = 3600

# Stage dependency graph: each stage maps to the set of stages it depends on.
# Used for topological layering to identify parallel execution opportunities.
STAGE_DEPS = {
    "subdomains": set(),
    "live_hosts": {"subdomains"},
    "waf": {"live_hosts"},
    "urls": {"live_hosts"},
    "parameters": {"urls"},
    "ranking": {"urls", "parameters", "waf"},
    "passive_scan": {"ranking", "live_hosts", "urls"},
    "active_scan": {"passive_scan"},
    "semgrep": {"passive_scan"},
    "nuclei": {"passive_scan"},
    "access_control": {"ranking", "passive_scan"},
    "validation": {"passive_scan", "active_scan"},
    "intelligence": {"passive_scan", "active_scan", "nuclei", "validation"},
    "reporting": {"intelligence", "nuclei", "access_control", "validation", "passive_scan"},
}

# Groups of stages that can execute in parallel.
# Each tuple is (after_stage, [parallel_stages]).
# After `after_stage` completes, all stages in the list can run concurrently.
PARALLEL_STAGE_GROUPS = [
    ("live_hosts", ["waf", "urls"]),
    ("passive_scan", ["nuclei", "access_control", "semgrep"]),
]


def _check_parallel_consistency() -> None:
    """Validate that PARALLEL_STAGE_GROUPS does not contradict STAGE_DEPS."""
    import logging

    _const_logger = logging.getLogger(__name__)
    for trigger, paral_stages in PARALLEL_STAGE_GROUPS:
        declared_deps = STAGE_DEPS.get(trigger, set())
        for stage in paral_stages:
            stage_deps = STAGE_DEPS.get(stage, set())
            if trigger not in stage_deps:
                _const_logger.warning(
                    "PARALLEL_STAGE_GROUPS: stage '%s' listed as parallel after '%s', "
                    "but STAGE_DEPS['%s']=%s does not include '%s' as a dependency. "
                    "This contradiction may cause incorrect execution ordering.",
                    stage,
                    trigger,
                    stage,
                    stage_deps,
                    trigger,
                )


_check_parallel_consistency()

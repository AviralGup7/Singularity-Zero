"""Recon pipeline facade exposing discovery, scoring, and nuclei functions.

Re-exports key recon functions for use by the platform orchestrator and
external callers.
"""

from src.recon.discovery import (
    build_focused_rescan_plan,
    run_enhanced_recon_layer,
    run_recon_layer,
)
from src.recon.favicon_fingerprint import fetch_favicons, lookup_faviconhash
from src.recon.filters import extract_parameters
from src.recon.graphql_introspection import (
    discover_graphql_endpoints,
    filter_introspection_ok,
)
from src.recon.live_hosts import (
    probe_host_without_httpx,
    probe_live_hosts,
    probe_live_hosts_fallback,
)
from src.recon.nuclei import build_nuclei_plan, run_nuclei
from src.recon.port_scanner import run_port_scan, run_port_scan_async
from src.recon.preview_deployments import discover_preview_deployments
from src.recon.scoring import (
    infer_target_profile,
    prioritize_urls,
    query_parameter_names,
    rank_urls,
    resolve_priority_limit,
    score_mode_bonus,
    score_url,
)
from src.recon.spa_detection import (
    detect_frameworks_from_content,
    probe_framework_endpoints,
)
from src.recon.subdomains import enumerate_subdomains, fetch_crtsh_subdomains
from src.recon.urls import collect_urls, emit_collection_progress

__all__ = [
    "build_focused_rescan_plan",
    "build_nuclei_plan",
    "collect_urls",
    "detect_frameworks_from_content",
    "discover_graphql_endpoints",
    "discover_preview_deployments",
    "emit_collection_progress",
    "enumerate_subdomains",
    "extract_parameters",
    "fetch_crtsh_subdomains",
    "fetch_favicons",
    "filter_introspection_ok",
    "infer_target_profile",
    "lookup_faviconhash",
    "prioritize_urls",
    "probe_framework_endpoints",
    "probe_host_without_httpx",
    "probe_live_hosts",
    "probe_live_hosts_fallback",
    "query_parameter_names",
    "rank_urls",
    "resolve_priority_limit",
    "run_enhanced_recon_layer",
    "run_nuclei",
    "run_port_scan",
    "run_port_scan_async",
    "run_recon_layer",
    "score_mode_bonus",
    "score_url",
]

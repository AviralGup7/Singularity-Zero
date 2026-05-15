"""Recon pipeline facade exposing discovery, scoring, and nuclei functions.

Re-exports key recon functions for use by the platform orchestrator and
external callers.
"""

from src.recon.live_hosts import (
    probe_host_without_httpx,
    probe_live_hosts,
    probe_live_hosts_fallback,
)
from src.recon.nuclei import build_nuclei_plan, run_nuclei
from src.recon.scoring import (
    infer_target_profile,
    prioritize_urls,
    query_parameter_names,
    rank_urls,
    resolve_priority_limit,
    score_mode_bonus,
    score_url,
)
from src.recon.subdomains import enumerate_subdomains, fetch_crtsh_subdomains
from src.recon.urls import collect_urls, emit_collection_progress, extract_parameters

__all__ = [
    "build_nuclei_plan",
    "collect_urls",
    "emit_collection_progress",
    "enumerate_subdomains",
    "extract_parameters",
    "fetch_crtsh_subdomains",
    "infer_target_profile",
    "prioritize_urls",
    "probe_host_without_httpx",
    "probe_live_hosts",
    "probe_live_hosts_fallback",
    "query_parameter_names",
    "rank_urls",
    "resolve_priority_limit",
    "run_nuclei",
    "score_mode_bonus",
    "score_url",
]

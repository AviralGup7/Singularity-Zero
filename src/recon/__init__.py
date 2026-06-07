"""Recon package facade.

Re-exports the public symbols of the recon module so that callers can
write ``from src.recon import run_enhanced_recon_layer`` etc.
"""

from src.recon.alienurl import (
    collect_archive_urls,
    run_aggregated_archive,
    run_alienurl_cli,
)
from src.recon.api_spec_discovery import (
    discover_api_specs,
    extract_operation_summaries,
    merge_openapi_specs,
)
from src.recon.asn_expansion import (
    asn_for_host,
    asn_for_url,
    asnmap_cli,
    expand_ips_to_cidrs,
    mapcidr_cli,
)
from src.recon.azure_sas import (
    AzureReconResult,
    AzureSasUrlPattern,
    run_azure_recon_sync,
    scan_azure_accounts,
)
from src.recon.discovery import (
    build_focused_rescan_plan,
    run_enhanced_recon_layer,
    run_recon_layer,
)
from src.recon.dnsx_wildcard import (
    WildcardFilterResult,
    detect_wildcard_async,
    detect_wildcard_sync,
    filter_subdomains_async,
    filter_subdomains_sync,
    is_public_ip,
    merge_wildcard_results,
    run_dnsx_cli,
)
from src.recon.favicon_fingerprint import (
    fetch_favicons,
    lookup_faviconhash,
    mmh3_hash_32,
)
from src.recon.filters import extract_parameters
from src.recon.focused_rescan import build_focused_rescan_plan as _build_focused_rescan_plan
from src.recon.graphql_introspection import (
    GraphQLEndpoint,
    discover_graphql_endpoints,
    filter_introspection_ok,
    introspect_endpoint_async,
    summarize_endpoints,
)
from src.recon.ja3_fingerprint import (
    identify_origin_stack,
    scan_targets_for_origin_leak,
)
from src.recon.js_parsers_v2 import (
    extract_endpoint_calls,
    extract_endpoints_v2,
    extract_html_attribute_endpoints,
    extract_source_map_url,
    extract_sources_content,
    extract_websocket_endpoints,
)
from src.recon.live_hosts import (
    probe_host_without_httpx,
    probe_live_hosts,
    probe_live_hosts_fallback,
)
from src.recon.models import ReconCandidate
from src.recon.nuclei import (
    build_nuclei_plan,
    build_nuclei_plan_with_param_map,
    run_nuclei,
    run_nuclei_jsonl,
    run_nuclei_with_parsing,
)
from src.recon.port_scanner import (
    DEFAULT_TOP_PORTS,
    host_in_scope,
    parse_portspec,
    run_naabu_cli,
    run_port_scan,
    run_port_scan_async,
    socket_port_scan,
)
from src.recon.preview_deployments import (
    all_candidates_for_project,
    discover_preview_deployments,
)
from src.recon.scoring import (
    infer_target_profile,
    prioritize_urls,
    query_parameter_names,
    rank_urls,
    resolve_priority_limit,
    score_mode_bonus,
    score_url,
)
from src.recon.shodan_censys import cross_reference_domain, cross_reference_ips
from src.recon.spa_detection import (
    FrameworkHit,
    collect_recommended_paths,
    detect_frameworks_from_content,
    probe_framework_endpoints,
    spa_aware_extra_urls,
)
from src.recon.standardize import standardize_recon_outputs
from src.recon.subdomain_permutator import (
    generate_permutations,
    run_alterx_cli,
)
from src.recon.subdomains import enumerate_subdomains, fetch_crtsh_subdomains
from src.recon.url_weighting import (
    combined_score,
    recency_score,
    sort_urls_by_weight,
    trim_urls,
)
from src.recon.url_weighting import (
    score_url as score_url_weighted,
)
from src.recon.urls import collect_urls, emit_collection_progress

__all__ = [
    "AzureReconResult",
    "AzureSasUrlPattern",
    "DEFAULT_TOP_PORTS",
    "FrameworkHit",
    "GraphQLEndpoint",
    "ReconCandidate",
    "WildcardFilterResult",
    "_build_focused_rescan_plan",
    "all_candidates_for_project",
    "asn_for_host",
    "asn_for_url",
    "asnmap_cli",
    "build_focused_rescan_plan",
    "build_nuclei_plan",
    "build_nuclei_plan_with_param_map",
    "collect_archive_urls",
    "collect_recommended_paths",
    "collect_urls",
    "combined_score",
    "cross_reference_domain",
    "cross_reference_ips",
    "detect_frameworks_from_content",
    "detect_wildcard_async",
    "detect_wildcard_sync",
    "discover_api_specs",
    "discover_graphql_endpoints",
    "discover_preview_deployments",
    "emit_collection_progress",
    "enumerate_subdomains",
    "expand_ips_to_cidrs",
    "extract_endpoint_calls",
    "extract_endpoints_v2",
    "extract_html_attribute_endpoints",
    "extract_operation_summaries",
    "extract_parameters",
    "extract_source_map_url",
    "extract_sources_content",
    "extract_websocket_endpoints",
    "fetch_crtsh_subdomains",
    "fetch_favicons",
    "filter_introspection_ok",
    "filter_subdomains_async",
    "filter_subdomains_sync",
    "generate_permutations",
    "host_in_scope",
    "identify_origin_stack",
    "infer_target_profile",
    "introspect_endpoint_async",
    "is_public_ip",
    "lookup_faviconhash",
    "mapcidr_cli",
    "merge_openapi_specs",
    "merge_wildcard_results",
    "mmh3_hash_32",
    "parse_portspec",
    "prioritize_urls",
    "probe_framework_endpoints",
    "probe_host_without_httpx",
    "probe_live_hosts",
    "probe_live_hosts_fallback",
    "query_parameter_names",
    "rank_urls",
    "recency_score",
    "run_aggregated_archive",
    "run_alienurl_cli",
    "run_alterx_cli",
    "run_azure_recon_sync",
    "run_dnsx_cli",
    "run_enhanced_recon_layer",
    "run_naabu_cli",
    "run_nuclei",
    "run_nuclei_jsonl",
    "run_nuclei_with_parsing",
    "run_port_scan",
    "run_port_scan_async",
    "run_recon_layer",
    "scan_azure_accounts",
    "scan_targets_for_origin_leak",
    "score_mode_bonus",
    "score_url",
    "score_url_weighted",
    "socket_port_scan",
    "sort_urls_by_weight",
    "spa_aware_extra_urls",
    "standardize_recon_outputs",
    "summarize_endpoints",
    "trim_urls",
]

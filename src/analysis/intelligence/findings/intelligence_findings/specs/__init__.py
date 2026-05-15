"""Finding spec registry for intelligence merge system."""

from collections.abc import Callable
from typing import Any

from src.analysis.helpers import build_manual_hint

from . import (
    access_boundary,
    admin_panel,
    ai_surface,
    api_version,
    auth_boundary_redirect,
    auth_header_tampering,
    backup_file,
    bulk_endpoint,
    cache_control,
    cache_poisoning,
    cdn_waf_gap,
    cloud_storage,
    cookie_security,
    cors_misconfig,
    cors_preflight,
    cross_tenant_pii,
    cross_user_access,
    csp_weakness,
    debug_artifacts,
    default_credentials,
    dev_staging,
    directory_listing,
    dns_misconfig,
    email_leakage,
    env_file,
    error_inference,
    error_stack_trace,
    exposed_service,
    filter_parameter_fuzzer,
    flow_integrity,
    frontend_config,
    graphql_active,
    graphql_errors,
    graphql_introspection,
    graphql_introspection_check,
    grpc_reflection,
    head_method,
    header_checker,
    hsts_weakness,
    http_method_exposure,
    http_method_override,
    json_mutation,
    jsonp_endpoint,
    locale_debug,
    log_file,
    logout_invalidation,
    multi_endpoint_auth,
    multi_step_flow,
    nested_object_traversal,
    nonstandard_service,
    openapi_swagger,
    options_method,
    origin_reflection,
    pagination_walker,
    parameter_dependency,
    parameter_pollution,
    parameter_pollution_exploit,
    password_flow,
    payment_provider,
    privilege_escalation,
    public_repo,
    race_condition,
    rate_limit_headers,
    rate_limit_signals,
    redirect_chain,
    referer_propagation,
    referrer_policy,
    reflected_xss,
    response_size_anomaly,
    response_structure,
    role_based_endpoint,
    semgrep,
    server_side_injection,
    service_worker,
    session_reuse,
    sqli_safe,
    state_transition,
    stored_xss,
    subdomain_takeover,
    third_party_key,
    tls_ssl,
    token_scope,
    trace_method,
    unauth_access,
    version_diffing,
    websocket_endpoint,
)

# Type alias for spec tuples
SpecTuple = tuple[
    str,  # module name
    str,  # category
    Callable[[dict[str, Any]], str],  # severity function
    str,  # title
    Callable[[dict[str, Any]], str],  # description/next_step function
]

# Registry of all specs - populated by importing all spec modules
SPECS: list[SpecTuple] = []


def register_spec(spec: SpecTuple) -> None:
    """Register a spec tuple."""
    SPECS.append(spec)


def get_all_specs() -> list[SpecTuple]:
    """Get all registered specs."""
    return list(SPECS)


# Import all spec modules to populate the registry

__all__ = ["SpecTuple", "register_spec", "get_all_specs", "SPECS"]

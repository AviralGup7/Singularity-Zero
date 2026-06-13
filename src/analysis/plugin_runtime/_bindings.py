"""Analyzer bindings registry for the plugin runtime engine.

Uses lazy imports to avoid loading all analyzer modules at startup.
"""

from collections.abc import Callable
from typing import Any

from src.analysis.plugin_runtime_models import AnalyzerBinding
from src.core.plugins import list_plugins, register_plugin

ANALYZER_BINDING = "analyzer_binding"

_BINDINGS_REGISTERED = False


def _binding(
    input_kind: str,
    runner: Callable[..., list[dict[str, Any]]] | None = None,
    *,
    context_attr: str | None = None,
    limit_key: str | None = None,
    default_limit: int | None = None,
    extra_kwargs: dict[str, object] | None = None,
    phase: str = "discover",
    consumes: tuple[str, ...] = (),
    produces: tuple[str, ...] = (),
) -> AnalyzerBinding:
    """Create an analyzer binding for the plugin runtime engine."""
    return AnalyzerBinding(
        input_kind=input_kind,
        runner=runner,
        context_attr=context_attr,
        limit_key=limit_key,
        default_limit=default_limit,
        extra_kwargs=extra_kwargs,
        phase=phase,
        consumes=consumes,
        produces=produces,
    )


def _lazy_import(module_path: str, attr_name: str) -> Callable[..., Any]:
    """Return a callable that lazily imports and returns the attribute."""
    def _loader(*args: Any, **kwargs: Any) -> Any:
        import importlib
        module = importlib.import_module(module_path)
        func = getattr(module, attr_name)
        return func(*args, **kwargs)
    return _loader


def _register_bindings() -> None:
    global _BINDINGS_REGISTERED
    if _BINDINGS_REGISTERED:
        return

    # Lazy-loaded bindings: (module_path, attr_name) pairs
    lazy_bindings = {
        # Passive detectors
        "header_checker": ("src.analysis.checks.passive._detectors", "header_checker"),
        "cookie_security_checker": ("src.analysis.checks.passive._detectors", "cookie_security_checker"),
        "cors_misconfig_checker": ("src.analysis.checks.passive._detectors", "cors_misconfig_checker"),
        "cache_control_checker": ("src.analysis.checks.passive._detectors", "cache_control_checker"),
        "jsonp_endpoint_checker": ("src.analysis.checks.passive._detectors", "jsonp_endpoint_checker"),
        "frontend_config_exposure_checker": ("src.analysis.checks.passive._detectors", "frontend_config_exposure_checker"),
        "directory_listing_checker": ("src.analysis.checks.passive._detectors", "directory_listing_checker"),
        "debug_artifact_checker": ("src.analysis.checks.passive._detectors", "debug_artifact_checker"),
        "stored_xss_signal_detector": ("src.analysis.checks.active._detectors", "stored_xss_signal_detector"),
        "dom_xss_signal_detector": ("src.analysis.checks.active._detectors", "dom_xss_signal_detector"),
        "ai_endpoint_exposure_analyzer": ("src.analysis.checks.active._detectors", "ai_endpoint_exposure_analyzer"),
        "server_side_injection_surface_analyzer": ("src.analysis.checks.active._detectors", "server_side_injection_surface_analyzer"),
        "reflected_xss_probe": ("src.analysis.checks.active._detectors", "reflected_xss_probe"),

        # Active checks
        "access_control_analyzer": ("src.analysis.checks.active.access_control_analyzer", "access_control_analyzer"),
        "auth_bypass_check": ("src.analysis.checks.active.auth_bypass_check", "auth_bypass_check"),
        "email_header_injection_probe": ("src.analysis.checks.active.email_header_injection", "email_header_injection_probe"),
        "file_upload_active_probe": ("src.analysis.checks.active.file_upload_probe", "file_upload_active_probe"),
        "idor_active_probe": ("src.analysis.checks.active.idor_probe", "idor_active_probe"),
        "jwt_security_analyzer": ("src.analysis.checks.active.jwt", "jwt_security_analyzer"),
        "ssrf_oob_validator": ("src.analysis.checks.active.ssrf_oob_validator", "ssrf_oob_validator"),
        "xml_bomb_detector": ("src.analysis.checks.active.xml_bomb_detector", "xml_bomb_detector"),

        # Passive detectors (separate module)
        "app_ssrf_scan": ("src.analysis.passive.detectors.detector_app_ssrf", "scan_responses"),
        "clickjacking_detector": ("src.analysis.passive.detectors.detector_clickjacking", "clickjacking_detector"),
        "csrf_protection_checker": ("src.analysis.passive.detectors.detector_csrf", "csrf_protection_checker"),
        "graphql_introspection_detector": ("src.analysis.passive.detectors.detector_graphql", "graphql_introspection_detector"),
        "logging_security_detector": ("src.analysis.passive.detectors.detector_logging", "logging_security_detector"),
        "oauth_misconfiguration_detector": ("src.analysis.passive.detectors.detector_oauth", "oauth_misconfiguration_detector"),
        "open_redirect_detector": ("src.analysis.passive.detectors.detector_open_redirect", "open_redirect_detector"),
        "sql_error_exposure_detector": ("src.analysis.passive.detectors.detector_sqli", "sql_error_exposure_detector"),
        "ssti_surface_detector": ("src.analysis.passive.detectors.detector_ssti", "ssti_surface_detector"),
        "file_upload_surface_detector": ("src.analysis.passive.detectors.detector_upload", "file_upload_surface_detector"),
        "vulnerable_component_detector": ("src.analysis.passive.detectors.detector_vulnerable_components", "vulnerable_component_detector"),
        "xxe_surface_detector": ("src.analysis.passive.detectors.detector_xxe", "xxe_surface_detector"),

        # JSON analysis
        "access_boundary_tracker": ("src.analysis.json._core.json_analysis", "access_boundary_tracker"),
        "bulk_endpoint_detector": ("src.analysis.json._core.json_analysis", "bulk_endpoint_detector"),
        "cross_tenant_pii_risk_analyzer": ("src.analysis.json._core.json_analysis", "cross_tenant_pii_risk_analyzer"),
        "cross_user_access_simulation": ("src.analysis.json._core.json_analysis", "cross_user_access_simulation"),
        "endpoint_resource_groups": ("src.analysis.json._core.json_analysis", "endpoint_resource_groups"),
        "json_response_parser": ("src.analysis.json._core.json_analysis", "json_response_parser"),
        "json_schema_inference": ("src.analysis.json._core.json_analysis", "json_schema_inference"),
        "nested_object_traversal": ("src.analysis.json._core.json_analysis", "nested_object_traversal"),
        "privilege_escalation_detector": ("src.analysis.json._core.json_analysis", "privilege_escalation_detector"),
        "response_structure_validator": ("src.analysis.json._core.json_analysis", "response_structure_validator"),
        "role_based_endpoint_comparison": ("src.analysis.json._core.json_analysis", "role_based_endpoint_comparison"),
        "role_context_diff": ("src.analysis.json._core.json_analysis", "role_context_diff"),
        "sensitive_field_detector": ("src.analysis.json._core.json_analysis", "sensitive_field_detector"),

        # Active injection probes
        "cookie_manipulation_probe": ("src.analysis.active.brute_force.cookie_manipulation", "cookie_manipulation_probe"),
        "command_injection_active_probe": ("src.analysis.active.injection.command_injection", "command_injection_active_probe"),
        "crlf_injection_probe": ("src.analysis.active.injection.crlf", "crlf_injection_probe"),
        "csrf_active_probe": ("src.analysis.active.injection.csrf", "csrf_active_probe"),
        "deserialization_probe": ("src.analysis.active.injection.deserialization", "deserialization_probe"),
        "host_header_injection_probe": ("src.analysis.active.injection.host_header", "host_header_injection_probe"),
        "jwt_manipulation_probe": ("src.analysis.active.injection.jwt_manipulation", "jwt_manipulation_probe"),
        "nosql_injection_probe": ("src.analysis.active.injection.nosql", "nosql_injection_probe"),
        "open_redirect_active_probe": ("src.analysis.active.injection.open_redirect", "open_redirect_active_probe"),
        "hpp_active_probe": ("src.analysis.active.injection.parameter_pollution", "hpp_active_probe"),
        "path_traversal_active_probe": ("src.analysis.active.injection.path_traversal", "path_traversal_active_probe"),
        "proxy_ssrf_probe": ("src.analysis.active.injection.proxy_ssrf", "proxy_ssrf_probe"),
        "sqli_safe_probe": ("src.analysis.active.injection.sqli", "sqli_safe_probe"),
        "ssrf_active_probe": ("src.analysis.active.injection.ssrf", "ssrf_active_probe"),
        "ssti_active_probe": ("src.analysis.active.injection.ssti", "ssti_active_probe"),
        "websocket_hijacking_probe": ("src.analysis.active.injection.websocket_hijacking", "websocket_hijacking_probe"),
        "xpath_injection_active_probe": ("src.analysis.active.injection.xpath", "xpath_injection_active_probe"),
        "xxe_active_probe": ("src.analysis.active.injection.xxe", "xxe_active_probe"),
        "param_mining_probe": ("src.analysis.active.param_mining", "param_mining_probe"),
        "run_cognitive_flow_analysis": ("src.analysis.behavior.flow_prober", "run_cognitive_flow_analysis"),

        # Detection handlers
        "js_sink_source_analyzer": ("src.detection.handlers", "js_sink_source_analyzer"),
        "wasm_module_introspector": ("src.detection.handlers", "wasm_module_introspector"),
        "prototype_pollution_walker": ("src.detection.handlers", "prototype_pollution_walker"),
        "dom_runtime_analyzer": ("src.detection.handlers", "dom_runtime_analyzer"),
        "waf_fingerprint_analyzer": ("src.detection.handlers", "waf_fingerprint_analyzer"),
        "waf_challenge_detector": ("src.detection.handlers", "waf_challenge_detector"),
        "csrf_entropy_analyzer": ("src.detection.handlers", "csrf_entropy_analyzer"),
        "session_fixation_detector": ("src.detection.handlers", "session_fixation_detector"),
        "rate_limit_adaptive_prober": ("src.detection.handlers", "rate_limit_adaptive_prober"),
        "race_concurrent_mutator": ("src.detection.handlers", "race_concurrent_mutator"),
        "api_rest_param_pollution": ("src.detection.handlers", "api_rest_param_pollution"),
        "api_graphql_introspection": ("src.detection.handlers", "api_graphql_introspection"),
        "api_rate_limit_differential": ("src.detection.handlers", "api_rate_limit_differential"),
        "api_jwt_claim_integrity": ("src.detection.handlers", "api_jwt_claim_integrity"),
        "api_websocket_message_security": ("src.detection.handlers", "api_websocket_message_security"),
    }

    # Bindings without lazy imports (no runner or inline runner)
    inline_bindings = {
        "sensitive_data_scanner": _binding("responses_only"),
        "token_leak_detector": _binding("responses_only"),
        "business_logic_tampering_detector": _binding("responses_only"),
        "rate_limit_bypass_detector": _binding("ranked_items_and_cache", limit_key="rate_limit_probe_limit", default_limit=10),
        "http_smuggling_detector": _binding("ranked_items_and_cache", limit_key="smuggling_probe_limit", default_limit=8),
        "ssrf_candidate_finder": _binding("urls_only"),
        "idor_candidate_finder": _binding("urls_only"),
        "technology_fingerprint": _binding("responses_only"),
        "anomaly_detector": _binding("urls_and_responses"),
        "response_snapshot_system": _binding("responses_only"),
        "response_diff_engine": _binding("priority_urls_and_cache"),
        "parameter_pollution_exploitation": _binding("priority_urls_and_cache"),
        "auth_header_tampering_variations": _binding("priority_urls_and_cache"),
        "http_method_override_probe": _binding("priority_urls_and_cache"),
        "json_mutation_attacks": _binding("priority_urls_and_cache"),
        "post_body_mutation_attacks": _binding("priority_urls_and_cache"),
        "flow_detector": _binding("urls_and_responses"),
        "multi_step_flow_breaking_probe": _binding("priority_urls_and_cache"),
        "session_reuse_detection": _binding("responses_only"),
        "logout_invalidation_check": _binding("responses_only"),
        "multi_endpoint_auth_consistency_check": _binding("responses_only"),
        "token_scope_analyzer": _binding("responses_only"),
        "referer_propagation_tracking": _binding("responses_only"),
        "pagination_walker": _binding("responses_only"),
        "filter_parameter_fuzzer": _binding("responses_only"),
        "error_based_inference": _binding("responses_only"),
        "state_transition_analyzer": _binding("responses_only"),
        "parameter_dependency_tracker": _binding("responses_only"),
        "flow_integrity_checker": _binding("responses_only"),
        "race_condition_signal_analyzer": _binding("responses_only"),
        "version_diffing": _binding("responses_only"),
        "unauth_access_check": _binding("responses_only"),
        "rate_limit_signal_analyzer": _binding("responses_and_bulk_items"),
        "rate_limit_header_analyzer": _binding("responses_only"),
        "response_size_anomaly_detector": _binding("responses_only"),
        "payment_flow_intelligence": _binding("responses_only"),
        "payment_provider_detection": _binding("responses_only"),
        "behavior_analysis_layer": _binding("behavior_analysis"),
        "cognitive_flow_analysis": _binding("urls_and_cache", limit_key="cognitive_flow_limit", default_limit=12),
        "redirect_chain_analyzer": _binding("responses_only"),
        "auth_boundary_redirect_detection": _binding("priority_urls_and_cache"),
        "graphql_error_leakage_checker": _binding("responses_only"),
        "openapi_swagger_spec_checker": _binding("urls_and_responses"),
        "grpc_reflection_exposure_checker": _binding("urls_and_responses"),
        "cloud_storage_exposure_checker": _binding("responses_only"),
        "cloud_metadata_exposure_checker": _binding("urls_and_responses"),
        "subdomain_takeover_indicator_checker": _binding("responses_only"),
        "service_worker_misconfiguration_checker": _binding("responses_only"),
        "csp_weakness_analyzer": _binding("responses_only"),
        "referrer_policy_weakness_checker": _binding("responses_only"),
        "hsts_weakness_checker": _binding("responses_only"),
        "dns_misconfiguration_signal_checker": _binding("responses_only"),
        "email_leakage_detector": _binding("responses_only"),
        "api_version_disclosure_checker": _binding("responses_only"),
        "password_confirmation_checker": _binding("responses_only"),
        "cache_poisoning_indicator_checker": _binding("responses_only"),
        "error_stack_trace_detector": _binding("responses_only"),
        "cdn_waf_fingerprint_gap_checker": _binding("responses_only"),
        "public_repo_exposure_checker": _binding("responses_only"),
        "backup_file_exposure_checker": _binding("responses_only"),
        "environment_file_exposure_checker": _binding("responses_only"),
        "log_file_exposure_checker": _binding("responses_only"),
        "websocket_endpoint_discovery": _binding("responses_only"),
        "http_method_exposure_checker": _binding("responses_only"),
        "parameter_pollution_indicator_checker": _binding("responses_only"),
        "locale_debug_toggle_checker": _binding("responses_only"),
        "third_party_key_exposure_checker": _binding("responses_only"),
        "options_method_probe": _binding("priority_urls_and_cache"),
        "origin_reflection_probe": _binding("priority_urls_and_cache"),
        "head_method_probe": _binding("priority_urls_and_cache"),
        "cors_preflight_probe": _binding("priority_urls_and_cache"),
        "trace_method_probe": _binding("priority_urls_and_cache"),
        "graphql_active_probe": _binding("priority_urls_and_cache"),
        "graphql_introspection_check": _binding("priority_urls_and_cache", limit_key="graphql_introspection_limit", default_limit=10),
        "http_smuggling_probe": _binding("priority_urls_and_cache", limit_key="smuggling_probe_limit", default_limit=10),
        "http2_probe": _binding("priority_urls_and_cache", limit_key="http2_probe_limit", default_limit=8),
        "oauth_flow_analyzer": _binding("priority_urls_and_cache", limit_key="oauth_probe_limit", default_limit=10),
        "websocket_message_probe": _binding("priority_urls_and_cache", limit_key="websocket_probe_limit", default_limit=8),
        "smart_payload_suggestions": _binding("priority_urls_only", context_attr="priority_urls", limit_key="payload_suggestion_limit", default_limit=18, extra_kwargs={}),
        "dns_record_analyzer": _binding("urls_and_responses"),
        "clickjacking_test": _binding("priority_urls_and_cache", limit_key="clickjacking_limit", default_limit=20),
        "ldap_injection_surface_analyzer": _binding("responses_only"),
        "token_lifetime_analyzer": _binding("responses_only"),
        "mass_assignment_detector": _binding("priority_urls_and_cache", limit_key="mass_assignment_limit", default_limit=10),
        "cache_deception_probe": _binding("priority_urls_and_cache", limit_key="cache_deception_limit", default_limit=12),
        "deserialization_language_probe": _binding("priority_urls_and_cache", limit_key="deserialization_lang_limit", default_limit=8),
        "tenant_isolation_check": _binding("priority_urls_and_cache", limit_key="tenant_isolation_limit", default_limit=10),
    }

    # Register lazy bindings
    for key, (module_path, attr_name) in lazy_bindings.items():
        runner = _lazy_import(module_path, attr_name)
        binding = _binding(
            "responses_only" if "checker" in key or "detector" in key else "urls_and_responses",
            runner,
        )
        register_plugin(ANALYZER_BINDING, key)(binding)

    # Register inline bindings
    for key, binding in inline_bindings.items():
        register_plugin(ANALYZER_BINDING, key)(binding)

    _BINDINGS_REGISTERED = True


def _get_bindings() -> dict[str, AnalyzerBinding]:
    _register_bindings()
    return {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}


ANALYZER_BINDINGS = _get_bindings()

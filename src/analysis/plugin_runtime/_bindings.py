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


class LazyRunner:
    def __init__(self, module_path: str, attr_name: str):
        self.module_path = module_path
        self.attr_name = attr_name

    def __lazy_resolve__(self) -> Any:
        import importlib

        module = importlib.import_module(self.module_path)
        return getattr(module, self.attr_name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.__lazy_resolve__()(*args, **kwargs)


def _lazy_import(module_path: str, attr_name: str) -> Callable[..., Any]:
    """Return a callable that lazily imports and returns the attribute."""
    return LazyRunner(module_path, attr_name)  # type: ignore[return-value]


def _register_bindings() -> None:
    global _BINDINGS_REGISTERED
    if _BINDINGS_REGISTERED:
        return

    # Lazy-loaded bindings: (module_path, attr_name, input_kind) tuples
    # input_kind is explicitly set per-binding to match the function signature
    lazy_bindings: dict[str, tuple[str, str, str]] = {
        # ---- Passive detectors (existing) ----
        "header_checker": (
            "src.analysis.checks.passive._detectors",
            "header_checker",
            "responses_only",
        ),
        "cookie_security_checker": (
            "src.analysis.checks.passive._detectors",
            "cookie_security_checker",
            "responses_only",
        ),
        "cors_misconfig_checker": (
            "src.analysis.checks.passive._detectors",
            "cors_misconfig_checker",
            "responses_only",
        ),
        "cache_control_checker": (
            "src.analysis.checks.passive._detectors",
            "cache_control_checker",
            "responses_only",
        ),
        "jsonp_endpoint_checker": (
            "src.analysis.checks.passive._detectors",
            "jsonp_endpoint_checker",
            "responses_only",
        ),
        "frontend_config_exposure_checker": (
            "src.analysis.checks.passive._detectors",
            "frontend_config_exposure_checker",
            "responses_only",
        ),
        "directory_listing_checker": (
            "src.analysis.checks.passive._detectors",
            "directory_listing_checker",
            "responses_only",
        ),
        "debug_artifact_checker": (
            "src.analysis.checks.passive._detectors",
            "debug_artifact_checker",
            "responses_only",
        ),
        # ---- Active detectors (existing) ----
        "stored_xss_signal_detector": (
            "src.analysis.checks.active._detectors",
            "stored_xss_signal_detector",
            "responses_only",
        ),
        "dom_xss_signal_detector": (
            "src.analysis.checks.active._detectors",
            "dom_xss_signal_detector",
            "responses_only",
        ),
        "ai_endpoint_exposure_analyzer": (
            "src.analysis.checks.active._detectors",
            "ai_endpoint_exposure_analyzer",
            "urls_and_responses",
        ),
        "server_side_injection_surface_analyzer": (
            "src.analysis.checks.active._detectors",
            "server_side_injection_surface_analyzer",
            "urls_and_responses",
        ),
        "reflected_xss_probe": (
            "src.analysis.checks.active._detectors",
            "reflected_xss_probe",
            "priority_urls_and_cache",
        ),
        # ---- Active checks (existing) ----
        "access_control_analyzer": (
            "src.analysis.checks.active.access_control_analyzer",
            "access_control_analyzer",
            "priority_urls_and_cache",
        ),
        "auth_bypass_check": (
            "src.analysis.checks.active.auth_bypass_check",
            "auth_bypass_check",
            "priority_urls_and_cache",
        ),
        "email_header_injection_probe": (
            "src.analysis.checks.active.email_header_injection",
            "email_header_injection_probe",
            "priority_urls_and_cache",
        ),
        "file_upload_active_probe": (
            "src.analysis.checks.active.file_upload_probe",
            "file_upload_active_probe",
            "priority_urls_and_cache",
        ),
        "idor_active_probe": (
            "src.analysis.checks.active.idor_probe",
            "idor_active_probe",
            "priority_urls_and_cache",
        ),
        "jwt_security_analyzer": (
            "src.analysis.checks.active.jwt",
            "jwt_security_analyzer",
            "priority_urls_and_cache",
        ),
        "ssrf_oob_validator": (
            "src.analysis.checks.active.ssrf_oob_validator",
            "ssrf_oob_validator",
            "priority_urls_and_cache",
        ),
        "xml_bomb_detector": (
            "src.analysis.checks.active.xml_bomb_detector",
            "xml_bomb_detector",
            "priority_urls_and_cache",
        ),
        # ---- Passive detectors (separate module, existing) ----
        "app_ssrf_scan": (
            "src.analysis.passive.detectors.detector_app_ssrf",
            "scan_responses",
            "responses_only",
        ),
        "clickjacking_detector": (
            "src.analysis.passive.detectors.detector_clickjacking",
            "clickjacking_detector",
            "responses_only",
        ),
        "csrf_protection_checker": (
            "src.analysis.passive.detectors.detector_csrf",
            "csrf_protection_checker",
            "responses_only",
        ),
        "graphql_introspection_detector": (
            "src.analysis.passive.detectors.detector_graphql",
            "graphql_introspection_detector",
            "responses_only",
        ),
        "logging_security_detector": (
            "src.analysis.passive.detectors.detector_logging",
            "logging_security_detector",
            "responses_only",
        ),
        "oauth_misconfiguration_detector": (
            "src.analysis.passive.detectors.detector_oauth",
            "oauth_misconfiguration_detector",
            "responses_only",
        ),
        "open_redirect_detector": (
            "src.analysis.passive.detectors.detector_open_redirect",
            "open_redirect_detector",
            "responses_only",
        ),
        "sql_error_exposure_detector": (
            "src.analysis.passive.detectors.detector_sqli",
            "sql_error_exposure_detector",
            "responses_only",
        ),
        "ssti_surface_detector": (
            "src.analysis.passive.detectors.detector_ssti",
            "ssti_surface_detector",
            "responses_only",
        ),
        "file_upload_surface_detector": (
            "src.analysis.passive.detectors.detector_upload",
            "file_upload_surface_detector",
            "responses_only",
        ),
        "vulnerable_component_detector": (
            "src.analysis.passive.detectors.detector_vulnerable_components",
            "vulnerable_component_detector",
            "urls_and_responses",
        ),
        "xxe_surface_detector": (
            "src.analysis.passive.detectors.detector_xxe",
            "xxe_surface_detector",
            "responses_only",
        ),
        # ---- JSON analysis (existing) ----
        "access_boundary_tracker": (
            "src.analysis.json._core.json_analysis",
            "access_boundary_tracker",
            "urls_and_responses",
        ),
        "bulk_endpoint_detector": (
            "src.analysis.json._core.json_analysis",
            "bulk_endpoint_detector",
            "responses_only",
        ),
        "cross_tenant_pii_risk_analyzer": (
            "src.analysis.json._core.json_analysis",
            "cross_tenant_pii_risk_analyzer",
            "urls_and_responses",
        ),
        "cross_user_access_simulation": (
            "src.analysis.json._core.json_analysis",
            "cross_user_access_simulation",
            "urls_and_responses",
        ),
        "endpoint_resource_groups": (
            "src.analysis.json._core.json_analysis",
            "endpoint_resource_groups",
            "responses_only",
        ),
        "json_response_parser": (
            "src.analysis.json._core.json_analysis",
            "json_response_parser",
            "responses_only",
        ),
        "json_schema_inference": (
            "src.analysis.json._core.json_analysis",
            "json_schema_inference",
            "responses_only",
        ),
        "nested_object_traversal": (
            "src.analysis.json._core.json_analysis",
            "nested_object_traversal",
            "responses_only",
        ),
        "privilege_escalation_detector": (
            "src.analysis.json._core.json_analysis",
            "privilege_escalation_detector",
            "priority_urls_and_cache",
        ),
        "response_structure_validator": (
            "src.analysis.json._core.json_analysis",
            "response_structure_validator",
            "responses_only",
        ),
        "role_based_endpoint_comparison": (
            "src.analysis.json._core.json_analysis",
            "role_based_endpoint_comparison",
            "urls_and_responses",
        ),
        "role_context_diff": (
            "src.analysis.json._core.json_analysis",
            "role_context_diff",
            "urls_and_responses",
        ),
        "sensitive_field_detector": (
            "src.analysis.json._core.json_analysis",
            "sensitive_field_detector",
            "responses_only",
        ),
        # ---- Active injection probes (existing) ----
        "command_injection_active_probe": (
            "src.analysis.active.injection.command_injection",
            "command_injection_active_probe",
            "priority_urls_and_cache",
        ),
        "crlf_injection_probe": (
            "src.analysis.active.injection.crlf",
            "crlf_injection_probe",
            "priority_urls_and_cache",
        ),
        "csrf_active_probe": (
            "src.analysis.active.injection.csrf",
            "csrf_active_probe",
            "priority_urls_and_cache",
        ),
        "deserialization_probe": (
            "src.analysis.active.injection.deserialization",
            "deserialization_probe",
            "priority_urls_and_cache",
        ),
        "host_header_injection_probe": (
            "src.analysis.active.injection.host_header",
            "host_header_injection_probe",
            "priority_urls_and_cache",
        ),
        "jwt_manipulation_probe": (
            "src.analysis.active.injection.jwt_manipulation",
            "jwt_manipulation_probe",
            "priority_urls_and_cache",
        ),
        "nosql_injection_probe": (
            "src.analysis.active.injection.nosql",
            "nosql_injection_probe",
            "priority_urls_and_cache",
        ),
        "open_redirect_active_probe": (
            "src.analysis.active.injection.open_redirect",
            "open_redirect_active_probe",
            "priority_urls_and_cache",
        ),
        "hpp_active_probe": (
            "src.analysis.active.injection.parameter_pollution",
            "hpp_active_probe",
            "priority_urls_and_cache",
        ),
        "path_traversal_active_probe": (
            "src.analysis.active.injection.path_traversal",
            "path_traversal_active_probe",
            "priority_urls_and_cache",
        ),
        "proxy_ssrf_probe": (
            "src.analysis.active.injection.proxy_ssrf",
            "proxy_ssrf_probe",
            "priority_urls_and_cache",
        ),
        "sqli_safe_probe": (
            "src.analysis.active.injection.sqli",
            "sqli_safe_probe",
            "priority_urls_and_cache",
        ),
        "ssrf_active_probe": (
            "src.analysis.active.injection.ssrf",
            "ssrf_active_probe",
            "priority_urls_and_cache",
        ),
        "ssti_active_probe": (
            "src.analysis.active.injection.ssti",
            "ssti_active_probe",
            "priority_urls_and_cache",
        ),
        "websocket_hijacking_probe": (
            "src.analysis.active.injection.websocket_hijacking",
            "websocket_hijacking_probe",
            "priority_urls_and_cache",
        ),
        "xpath_injection_active_probe": (
            "src.analysis.active.injection.xpath",
            "xpath_injection_active_probe",
            "priority_urls_and_cache",
        ),
        "xxe_active_probe": (
            "src.analysis.active.injection.xxe",
            "xxe_active_probe",
            "priority_urls_and_cache",
        ),
        # ---- Detection handlers (existing) ----
        "js_sink_source_analyzer": (
            "src.detection.handlers",
            "js_sink_source_analyzer",
            "responses_only",
        ),
        "wasm_module_introspector": (
            "src.detection.handlers",
            "wasm_module_introspector",
            "responses_only",
        ),
        "prototype_pollution_walker": (
            "src.detection.handlers",
            "prototype_pollution_walker",
            "responses_only",
        ),
        "dom_runtime_analyzer": (
            "src.detection.handlers",
            "dom_runtime_analyzer",
            "responses_only",
        ),
        "waf_fingerprint_analyzer": (
            "src.detection.handlers",
            "waf_fingerprint_analyzer",
            "responses_only",
        ),
        "waf_challenge_detector": (
            "src.detection.handlers",
            "waf_challenge_detector",
            "responses_only",
        ),
        "csrf_entropy_analyzer": (
            "src.detection.handlers",
            "csrf_entropy_analyzer",
            "responses_only",
        ),
        "session_fixation_detector": (
            "src.detection.handlers",
            "session_fixation_detector",
            "responses_only",
        ),
        "rate_limit_adaptive_prober": (
            "src.detection.handlers",
            "rate_limit_adaptive_prober",
            "responses_only",
        ),
        "race_concurrent_mutator": (
            "src.detection.handlers",
            "race_concurrent_mutator",
            "responses_only",
        ),
        "api_rest_param_pollution": (
            "src.detection.handlers",
            "api_rest_param_pollution",
            "responses_only",
        ),
        "api_graphql_introspection": (
            "src.detection.handlers",
            "api_graphql_introspection",
            "responses_only",
        ),
        "api_rate_limit_differential": (
            "src.detection.handlers",
            "api_rate_limit_differential",
            "responses_only",
        ),
        "api_jwt_claim_integrity": (
            "src.detection.handlers",
            "api_jwt_claim_integrity",
            "responses_only",
        ),
        "api_websocket_message_security": (
            "src.detection.handlers",
            "api_websocket_message_security",
            "responses_only",
        ),
        # ================================================================
        # REWIRED STUBS: Inline bindings with runner=None converted to
        # lazy-loaded bindings with actual implementations
        # ================================================================

        # ---- Passive detectors (previously inline stubs) ----
        "sensitive_data_scanner": (
            "src.analysis.checks.passive._detectors",
            "sensitive_data_scanner",
            "responses_only",
        ),
        "technology_fingerprint": (
            "src.analysis.checks.passive._detectors",
            "technology_fingerprint",
            "responses_only",
        ),
        "ldap_injection_surface_analyzer": (
            "src.analysis.checks.passive.ldap_injection",
            "ldap_injection_surface_analyzer",
            "responses_only",
        ),
        "token_lifetime_analyzer": (
            "src.analysis.checks.passive.token_lifetime_analyzer",
            "token_lifetime_analyzer",
            "responses_only",
        ),

        # ---- Passive detectors (separate module, previously inline) ----
        "token_leak_detector": (
            "src.analysis.passive.detectors.detector_token",
            "token_leak_detector",
            "urls_and_responses",
        ),
        "business_logic_tampering_detector": (
            "src.analysis.passive.detectors.detector_business_logic",
            "business_logic_tampering_detector",
            "urls_and_responses",
        ),
        "anomaly_detector": (
            "src.analysis.passive.detectors.detector_anomaly",
            "anomaly_detector",
            "urls_and_responses",
        ),
        "ssrf_candidate_finder": (
            "src.analysis.passive.detectors.detector_ssrf",
            "ssrf_candidate_finder",
            "urls_only",
        ),
        "idor_candidate_finder": (
            "src.analysis.passive.detectors.detector_idor",
            "idor_candidate_finder",
            "urls_and_cache",
        ),
        "race_condition_signal_analyzer": (
            "src.analysis.checks.active._detectors",
            "race_condition_signal_analyzer",
            "urls_and_responses",
        ),

        # ---- Response analysis (previously inline stubs) ----
        "response_snapshot_system": (
            "src.analysis.response._core.response_analysis._snapshot",
            "response_snapshot_system",
            "responses_only",
        ),
        "response_diff_engine": (
            "src.analysis.response._core.response_analysis._diff_engine",
            "response_diff_engine",
            "priority_urls_and_cache",
        ),
        "parameter_pollution_exploitation": (
            "src.analysis.response._core.response_analysis._parameter_pollution",
            "parameter_pollution_exploitation",
            "priority_urls_and_cache",
        ),
        "auth_header_tampering_variations": (
            "src.analysis.response._core.response_analysis._auth_tampering",
            "auth_header_tampering_variations",
            "priority_urls_and_cache",
        ),
        "http_method_override_probe": (
            "src.analysis.response._core.response_analysis._http_method_override",
            "http_method_override_probe",
            "priority_urls_and_cache",
        ),
        "json_mutation_attacks": (
            "src.analysis.response._core.response_analysis._json_mutations",
            "json_mutation_attacks",
            "priority_urls_and_cache",
        ),
        "post_body_mutation_attacks": (
            "src.analysis.response._core.response_analysis._json_mutations",
            "post_body_mutation_attacks",
            "priority_urls_and_cache",
        ),
        "flow_detector": (
            "src.analysis.response._core.response_analysis._flow_detection",
            "flow_detector",
            "urls_only",
        ),
        "multi_step_flow_breaking_probe": (
            "src.analysis.response._core.response_analysis._flow_detection",
            "multi_step_flow_breaking_probe",
            "behavior_analysis",
        ),
        "redirect_chain_analyzer": (
            "src.analysis.response._core.response_analysis._redirect_analysis",
            "redirect_chain_analyzer",
            "priority_urls_and_cache",
        ),

        # ---- JSON analysis (previously inline stubs) ----
        "session_reuse_detection": (
            "src.analysis.json.auth",
            "session_reuse_detection",
            "urls_and_responses",
        ),
        "logout_invalidation_check": (
            "src.analysis.json.auth",
            "logout_invalidation_check",
            "priority_urls_and_cache",
        ),
        "multi_endpoint_auth_consistency_check": (
            "src.analysis.json.auth",
            "multi_endpoint_auth_consistency_check",
            "responses_only",
        ),
        "unauth_access_check": (
            "src.analysis.json.auth",
            "unauth_access_check",
            "priority_urls_and_cache",
        ),
        "token_scope_analyzer": (
            "src.analysis.json.token_scope",
            "token_scope_analyzer",
            "responses_only",
        ),
        "referer_propagation_tracking": (
            "src.analysis.json.token_scope",
            "referer_propagation_tracking",
            "urls_and_responses",
        ),
        "pagination_walker": (
            "src.analysis.json.active_probes",
            "pagination_walker",
            "priority_urls_and_cache",
        ),
        "filter_parameter_fuzzer": (
            "src.analysis.json.active_probes",
            "filter_parameter_fuzzer",
            "priority_urls_and_cache",
        ),
        "error_based_inference": (
            "src.analysis.json.error_probe",
            "error_based_inference",
            "priority_urls_and_cache",
        ),
        "state_transition_analyzer": (
            "src.analysis.json.active_probes",
            "state_transition_analyzer",
            "priority_urls_and_cache",
        ),
        "parameter_dependency_tracker": (
            "src.analysis.json.active_probes",
            "parameter_dependency_tracker",
            "priority_urls_and_cache",
        ),
        "flow_integrity_checker": (
            "src.analysis.json.active_probes",
            "flow_integrity_checker",
            "behavior_analysis",
        ),
        "version_diffing": (
            "src.analysis.json.version_diff",
            "version_diffing",
            "urls_and_cache",
        ),
        "rate_limit_signal_analyzer": (
            "src.analysis.json.rate_limit",
            "rate_limit_signal_analyzer",
            "responses_and_bulk_items",
        ),
        "response_size_anomaly_detector": (
            "src.analysis.json.size_anomaly",
            "response_size_anomaly_detector",
            "responses_only",
        ),

        # ---- Active probes (previously inline stubs) ----
        "options_method_probe": (
            "src.analysis.active.http_methods",
            "options_method_probe",
            "priority_urls_and_cache",
        ),
        "origin_reflection_probe": (
            "src.analysis.active.http_methods",
            "origin_reflection_probe",
            "priority_urls_and_cache",
        ),
        "head_method_probe": (
            "src.analysis.active.http_methods",
            "head_method_probe",
            "priority_urls_and_cache",
        ),
        "cors_preflight_probe": (
            "src.analysis.active.http_methods",
            "cors_preflight_probe",
            "priority_urls_and_cache",
        ),
        "trace_method_probe": (
            "src.analysis.active.http_methods",
            "trace_method_probe",
            "priority_urls_and_cache",
        ),
        "graphql_active_probe": (
            "src.analysis.active.graphql.core",
            "graphql_active_probe",
            "priority_urls_and_cache",
        ),
        "graphql_introspection_check": (
            "src.analysis.checks.active.graphql_check",
            "graphql_introspection_check",
            "priority_urls_and_cache",
        ),
        "http2_probe": (
            "src.analysis.active.http_smuggling",
            "http2_probe",
            "priority_urls_and_cache",
        ),
        "oauth_flow_analyzer": (
            "src.analysis.active.coordinator",
            "oauth_flow_analyzer",
            "priority_urls_and_cache",
        ),
        "cookie_manipulation_probe": (
            "src.analysis.active.brute_force.cookie_manipulation",
            "cookie_manipulation_probe",
            "priority_urls_and_cache",
        ),
        "param_mining_probe": (
            "src.analysis.active.param_mining",
            "param_mining_probe",
            "priority_urls_and_cache",
        ),
        "clickjacking_test": (
            "src.analysis.checks.active.clickjacking_test",
            "clickjacking_test",
            "urls_and_responses",
        ),
        "mass_assignment_detector": (
            "src.analysis.checks.active.mass_assignment",
            "mass_assignment_detector",
            "priority_urls_and_cache",
        ),
        "cache_deception_probe": (
            "src.analysis.checks.active.cache_deception",
            "cache_deception_probe",
            "priority_urls_and_cache",
        ),
        "deserialization_language_probe": (
            "src.analysis.checks.active.deserialization_probe",
            "deserialization_probe",
            "urls_and_responses",
        ),
        "tenant_isolation_check": (
            "src.analysis.checks.active.tenant_isolation_check",
            "tenant_isolation_check",
            "priority_urls_and_cache",
        ),

        # ---- Exposure detectors (previously inline stubs) ----
        "graphql_error_leakage_checker": (
            "src.analysis.checks.exposure._api_surface",
            "graphql_error_leakage_checker",
            "responses_only",
        ),
        "openapi_swagger_spec_checker": (
            "src.analysis.checks.exposure._api_surface",
            "openapi_swagger_spec_checker",
            "urls_and_responses",
        ),
        "grpc_reflection_exposure_checker": (
            "src.analysis.checks.exposure._api_surface",
            "grpc_reflection_exposure_checker",
            "urls_and_responses",
        ),
        "cloud_storage_exposure_checker": (
            "src.analysis.checks.exposure._detectors",
            "cloud_storage_exposure_checker",
            "urls_and_responses",
        ),
        "cloud_metadata_exposure_checker": (
            "src.analysis.checks.exposure.cloud_metadata_check",
            "cloud_metadata_exposure_checker",
            "urls_and_responses",
        ),
        "service_worker_misconfiguration_checker": (
            "src.analysis.checks.exposure._detectors",
            "service_worker_misconfiguration_checker",
            "responses_only",
        ),
        "csp_weakness_analyzer": (
            "src.analysis.checks.exposure._detectors",
            "csp_weakness_analyzer",
            "responses_only",
        ),
        "referrer_policy_weakness_checker": (
            "src.analysis.checks.exposure._detectors",
            "referrer_policy_weakness_checker",
            "responses_only",
        ),
        "hsts_weakness_checker": (
            "src.analysis.checks.exposure._detectors",
            "hsts_weakness_checker",
            "responses_only",
        ),
        "dns_misconfiguration_signal_checker": (
            "src.analysis.checks.exposure._detectors",
            "dns_misconfiguration_signal_checker",
            "responses_only",
        ),
        "email_leakage_detector": (
            "src.analysis.checks.exposure._detectors",
            "email_leakage_detector",
            "responses_only",
        ),
        "api_version_disclosure_checker": (
            "src.analysis.checks.exposure._detectors",
            "api_version_disclosure_checker",
            "urls_only",
        ),
        "password_confirmation_checker": (
            "src.analysis.checks.exposure._detectors",
            "password_confirmation_checker",
            "urls_and_responses",
        ),
        "cache_poisoning_indicator_checker": (
            "src.analysis.checks.exposure._detectors",
            "cache_poisoning_indicator_checker",
            "responses_only",
        ),
        "error_stack_trace_detector": (
            "src.analysis.checks.exposure._detectors",
            "error_stack_trace_detector",
            "responses_only",
        ),
        "cdn_waf_fingerprint_gap_checker": (
            "src.analysis.checks.exposure._detectors",
            "cdn_waf_fingerprint_gap_checker",
            "responses_only",
        ),
        "public_repo_exposure_checker": (
            "src.analysis.checks.exposure._detectors",
            "public_repo_exposure_checker",
            "urls_and_responses",
        ),
        "backup_file_exposure_checker": (
            "src.analysis.checks.exposure._detectors",
            "backup_file_exposure_checker",
            "urls_and_responses",
        ),
        "environment_file_exposure_checker": (
            "src.analysis.checks.exposure._detectors",
            "environment_file_exposure_checker",
            "urls_and_responses",
        ),
        "log_file_exposure_checker": (
            "src.analysis.checks.exposure._detectors",
            "log_file_exposure_checker",
            "urls_and_responses",
        ),
        "websocket_endpoint_discovery": (
            "src.analysis.checks.exposure._detectors",
            "websocket_endpoint_discovery",
            "urls_and_responses",
        ),
        "http_method_exposure_checker": (
            "src.analysis.checks.exposure._detectors",
            "http_method_exposure_checker",
            "responses_only",
        ),
        "parameter_pollution_indicator_checker": (
            "src.analysis.checks.exposure._detectors",
            "parameter_pollution_indicator_checker",
            "urls_only",
        ),
        "locale_debug_toggle_checker": (
            "src.analysis.checks.exposure._detectors",
            "locale_debug_toggle_checker",
            "urls_only",
        ),
        "third_party_key_exposure_checker": (
            "src.analysis.checks.exposure._detectors",
            "third_party_key_exposure_checker",
            "responses_only",
        ),
        "rate_limit_header_analyzer": (
            "src.analysis.checks.exposure._detectors",
            "rate_limit_header_analyzer",
            "responses_only",
        ),
        "dns_record_analyzer": (
            "src.analysis.checks.exposure.dns_record_analyzer",
            "dns_record_analyzer",
            "urls_and_responses",
        ),

        # ---- Behavior analysis (previously inline stubs) ----
        "payment_flow_intelligence": (
            "src.analysis.behavior.payment",
            "payment_flow_intelligence",
            "urls_and_responses",
        ),
        "payment_provider_detection": (
            "src.analysis.behavior.payment",
            "payment_provider_detection",
            "responses_only",
        ),
        "run_cognitive_flow_analysis": (
            "src.analysis.behavior.flow_prober",
            "run_cognitive_flow_analysis",
            "urls_and_cache",
        ),
    }

    # Bindings with NO actual function definition (pure spec registrations).
    # These remain as inline bindings with runner=None. Their results are
    # populated by other code paths (behavior pipeline, orchestrator injection).
    inline_bindings = {
        "smart_payload_suggestions": _binding(
            "priority_urls_only",
            context_attr="priority_urls",
            limit_key="payload_suggestion_limit",
            default_limit=18,
            extra_kwargs={},
        ),
        "rate_limit_bypass_detector": _binding(
            "ranked_items_and_cache",
            limit_key="rate_limit_probe_limit",
            default_limit=10,
        ),
        "http_smuggling_detector": _binding(
            "ranked_items_and_cache",
            limit_key="smuggling_probe_limit",
            default_limit=8,
        ),
        "cognitive_flow_analysis": _binding(
            "urls_and_cache",
            limit_key="cognitive_flow_limit",
            default_limit=12,
        ),
        "behavior_analysis_layer": _binding("behavior_analysis"),
    }

    # Register lazy bindings
    for key, (module_path, attr_name, input_kind) in lazy_bindings.items():
        runner = _lazy_import(module_path, attr_name)
        binding = _binding(input_kind, runner)
        register_plugin(ANALYZER_BINDING, key)(binding)

    # Register inline bindings (pure stubs with no runner)
    for key, binding in inline_bindings.items():
        register_plugin(ANALYZER_BINDING, key)(binding)

    _BINDINGS_REGISTERED = True


def _get_bindings() -> dict[str, AnalyzerBinding]:
    _register_bindings()
    return {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}


ANALYZER_BINDINGS = _get_bindings()

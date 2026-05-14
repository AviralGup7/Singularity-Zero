"""Endpoint intelligence module registry.

Maps analysis module names to signal categories and defines
which modules contribute to endpoint intelligence building.
"""

__all__ = [
    "MODULE_SIGNAL_MAP",
    "REPRODUCIBLE_MODULES",
    "CONFIRMATION_MODULES",
    "DIFF_CHECK_MODULES",
]

# Maps module names to signal categories
MODULE_SIGNAL_MAP: dict[str, str] = {
    "token_leak_detector": "token",
    "ssrf_candidate_finder": "ssrf",
    "idor_candidate_finder": "idor",
    "sensitive_field_detector": "sensitive_data",
    "cross_user_access_simulation": "access_control",
    "role_based_endpoint_comparison": "access_control",
    "privilege_escalation_detector": "access_control",
    "access_boundary_tracker": "access_control",
    "bulk_endpoint_detector": "bulk",
    "pagination_walker": "pagination",
    "filter_parameter_fuzzer": "filter_diff",
    "error_based_inference": "error_inference",
    "session_reuse_detection": "session",
    "logout_invalidation_check": "session",
    "multi_endpoint_auth_consistency_check": "session",
    "token_scope_analyzer": "token",
    "referer_propagation_tracking": "token",
    "state_transition_analyzer": "business_logic",
    "parameter_dependency_tracker": "business_logic",
    "flow_integrity_checker": "business_logic",
    "version_diffing": "version_diff",
    "unauth_access_check": "unauth",
    "rate_limit_signal_analyzer": "rate_limit",
    "response_size_anomaly_detector": "size_anomaly",
    "nested_object_traversal": "nested_json",
    "payment_flow_intelligence": "payment",
    "payment_provider_detection": "payment",
    "header_checker": "misconfiguration",
    "cookie_security_checker": "misconfiguration",
    "cors_misconfig_checker": "cors",
    "cache_control_checker": "misconfiguration",
    "jsonp_endpoint_checker": "exposure",
    "frontend_config_exposure_checker": "exposure",
    "directory_listing_checker": "exposure",
    "debug_artifact_checker": "exposure",
    "stored_xss_signal_detector": "xss",
    "race_condition_signal_analyzer": "race",
    "anomaly_detector": "anomaly",
    "parameter_pollution_exploitation": "business_logic",
    "auth_header_tampering_variations": "auth_tamper",
    "http_method_override_probe": "auth_tamper",
    "json_mutation_attacks": "business_logic",
    "options_method_probe": "active_probe",
    "origin_reflection_probe": "cors",
    "head_method_probe": "active_probe",
    "cors_preflight_probe": "cors",
    "trace_method_probe": "active_probe",
    "reflected_xss_probe": "xss",
    "sqli_safe_probe": "sql_injection",
    "graphql_active_probe": "graphql",
    "graphql_introspection_check": "graphql",
    "redirect_chain_analyzer": "redirect",
    "auth_boundary_redirect_detection": "redirect",
    "multi_step_flow_breaking_probe": "business_logic",
    "csrf_protection_checker": "csrf",
    "ssti_surface_detector": "ssti",
    "file_upload_surface_detector": "file_upload",
}

# Modules that indicate reproducible findings
REPRODUCIBLE_MODULES = {
    "parameter_pollution_exploitation",
    "auth_header_tampering_variations",
    "http_method_override_probe",
    "json_mutation_attacks",
    "multi_step_flow_breaking_probe",
}

# Modules that indicate confirmed findings
CONFIRMATION_MODULES = {
    "privilege_escalation_detector",
    "pagination_walker",
    "filter_parameter_fuzzer",
    "error_based_inference",
    "parameter_pollution_exploitation",
    "auth_header_tampering_variations",
    "http_method_override_probe",
    "json_mutation_attacks",
    "state_transition_analyzer",
    "parameter_dependency_tracker",
    "version_diffing",
    "unauth_access_check",
    "multi_step_flow_breaking_probe",
}

# Modules that produce diff results
DIFF_CHECK_MODULES = {
    "privilege_escalation_detector",
    "pagination_walker",
    "filter_parameter_fuzzer",
    "error_based_inference",
    "parameter_pollution_exploitation",
    "auth_header_tampering_variations",
    "http_method_override_probe",
    "json_mutation_attacks",
    "state_transition_analyzer",
    "parameter_dependency_tracker",
    "version_diffing",
    "unauth_access_check",
    "multi_step_flow_breaking_probe",
}

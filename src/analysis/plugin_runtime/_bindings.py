"""Analyzer bindings registry for the plugin runtime engine."""

from collections.abc import Callable
from typing import Any

import src.detection.handlers
from src.analysis.active.brute_force.cookie_manipulation import cookie_manipulation_probe
from src.analysis.active.injection.command_injection import command_injection_active_probe
from src.analysis.active.injection.crlf import crlf_injection_probe
from src.analysis.active.injection.csrf import csrf_active_probe
from src.analysis.active.injection.deserialization import deserialization_probe
from src.analysis.active.injection.host_header import host_header_injection_probe
from src.analysis.active.injection.jwt_manipulation import jwt_manipulation_probe
from src.analysis.active.injection.nosql import nosql_injection_probe
from src.analysis.active.injection.open_redirect import open_redirect_active_probe
from src.analysis.active.injection.parameter_pollution import hpp_active_probe
from src.analysis.active.injection.path_traversal import path_traversal_active_probe
from src.analysis.active.injection.proxy_ssrf import proxy_ssrf_probe
from src.analysis.active.injection.sqli import sqli_safe_probe
from src.analysis.active.injection.ssrf import ssrf_active_probe
from src.analysis.active.injection.ssti import ssti_active_probe
from src.analysis.active.injection.websocket_hijacking import websocket_hijacking_probe
from src.analysis.active.injection.xpath import xpath_injection_active_probe
from src.analysis.active.injection.xxe import xxe_active_probe
from src.analysis.active.param_mining import param_mining_probe
from src.analysis.behavior.flow_prober import run_cognitive_flow_analysis
from src.analysis.checks.active._detectors import (
    ai_endpoint_exposure_analyzer,
    dom_xss_signal_detector,
    reflected_xss_probe,
    server_side_injection_surface_analyzer,
    stored_xss_signal_detector,
)
from src.analysis.checks.active.access_control_analyzer import access_control_analyzer
from src.analysis.checks.active.auth_bypass_check import auth_bypass_check
from src.analysis.checks.active.email_header_injection import email_header_injection_probe
from src.analysis.checks.active.file_upload_probe import file_upload_active_probe
from src.analysis.checks.active.idor_probe import idor_active_probe
from src.analysis.checks.active.jwt import jwt_security_analyzer
from src.analysis.checks.active.ssrf_oob_validator import ssrf_oob_validator
from src.analysis.checks.active.xml_bomb_detector import xml_bomb_detector
from src.analysis.checks.passive._detectors import (
    cache_control_checker,
    cookie_security_checker,
    cors_misconfig_checker,
    debug_artifact_checker,
    directory_listing_checker,
    frontend_config_exposure_checker,
    header_checker,
    jsonp_endpoint_checker,
)
from src.analysis.json._core.json_analysis import (
    access_boundary_tracker,
    bulk_endpoint_detector,
    cross_tenant_pii_risk_analyzer,
    cross_user_access_simulation,
    endpoint_resource_groups,
    json_response_parser,
    json_schema_inference,
    nested_object_traversal,
    privilege_escalation_detector,
    response_structure_validator,
    role_based_endpoint_comparison,
    role_context_diff,
    sensitive_field_detector,
)
from src.analysis.passive.detectors.detector_app_ssrf import scan_responses as app_ssrf_scan
from src.analysis.passive.detectors.detector_clickjacking import clickjacking_detector
from src.analysis.passive.detectors.detector_csrf import csrf_protection_checker
from src.analysis.passive.detectors.detector_graphql import graphql_introspection_detector
from src.analysis.passive.detectors.detector_logging import logging_security_detector
from src.analysis.passive.detectors.detector_oauth import oauth_misconfiguration_detector
from src.analysis.passive.detectors.detector_open_redirect import open_redirect_detector
from src.analysis.passive.detectors.detector_sqli import sql_error_exposure_detector
from src.analysis.passive.detectors.detector_ssti import ssti_surface_detector
from src.analysis.passive.detectors.detector_upload import file_upload_surface_detector
from src.analysis.passive.detectors.detector_vulnerable_components import (
    vulnerable_component_detector,
)
from src.analysis.passive.detectors.detector_xxe import xxe_surface_detector
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


def _register_bindings() -> None:
    global _BINDINGS_REGISTERED
    if _BINDINGS_REGISTERED:
        return

    bindings = {
        "sensitive_data_scanner": _binding("responses_only"),
        "header_checker": _binding("header_targets_and_cache", header_checker),
        "cookie_security_checker": _binding("responses_only", cookie_security_checker),
        "cors_misconfig_checker": _binding("responses_only", cors_misconfig_checker),
        "cache_control_checker": _binding("responses_only", cache_control_checker),
        "jsonp_endpoint_checker": _binding("responses_only", jsonp_endpoint_checker),
        "frontend_config_exposure_checker": _binding(
            "responses_only", frontend_config_exposure_checker
        ),
        "directory_listing_checker": _binding("responses_only", directory_listing_checker),
        "debug_artifact_checker": _binding("urls_and_responses", debug_artifact_checker),
        "stored_xss_signal_detector": _binding("responses_only", stored_xss_signal_detector),
        "dom_xss_signal_detector": _binding("responses_only", dom_xss_signal_detector),
        "token_leak_detector": _binding("responses_only"),
        "graphql_introspection_exposure_checker": _binding(
            "urls_and_responses", graphql_introspection_detector
        ),
        "csrf_protection_checker": _binding(
            "urls_and_responses",
            csrf_protection_checker,
        ),
        "ssti_surface_detector": _binding("urls_and_responses", ssti_surface_detector),
        "file_upload_surface_detector": _binding(
            "urls_and_responses", file_upload_surface_detector
        ),
        "vulnerable_component_detector": _binding(
            "urls_and_responses", vulnerable_component_detector
        ),
        "business_logic_tampering_detector": _binding("responses_only"),
        "sql_error_exposure_detector": _binding(
            "responses_only",
            sql_error_exposure_detector,
            phase="discover",
            consumes=("responses",),
            produces=("finding",),
        ),
        "rate_limit_bypass_detector": _binding(
            "ranked_items_and_cache",
            limit_key="rate_limit_probe_limit",
            default_limit=10,
        ),
        "jwt_security_analyzer": _binding(
            "priority_urls_and_cache",
            jwt_security_analyzer,
            limit_key="jwt_analysis_limit",
            default_limit=20,
        ),
        "http_smuggling_detector": _binding(
            "ranked_items_and_cache",
            limit_key="smuggling_probe_limit",
            default_limit=8,
        ),
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
        "cross_user_access_simulation": _binding("responses_only", cross_user_access_simulation),
        "role_based_endpoint_comparison": _binding(
            "responses_only", role_based_endpoint_comparison
        ),
        "privilege_escalation_detector": _binding(
            "priority_urls_and_cache", privilege_escalation_detector
        ),
        "access_boundary_tracker": _binding("responses_only", access_boundary_tracker),
        "session_reuse_detection": _binding("responses_only"),
        "logout_invalidation_check": _binding("responses_only"),
        "multi_endpoint_auth_consistency_check": _binding("responses_only"),
        "token_scope_analyzer": _binding("responses_only"),
        "referer_propagation_tracking": _binding("responses_only"),
        "sensitive_field_detector": _binding("responses_only", sensitive_field_detector),
        "nested_object_traversal": _binding("responses_only", nested_object_traversal),
        "endpoint_resource_groups": _binding("urls_only", endpoint_resource_groups),
        "bulk_endpoint_detector": _binding("urls_only", bulk_endpoint_detector),
        "pagination_walker": _binding("responses_only"),
        "filter_parameter_fuzzer": _binding("responses_only"),
        "error_based_inference": _binding("responses_only"),
        "state_transition_analyzer": _binding("responses_only"),
        "parameter_dependency_tracker": _binding("responses_only"),
        "flow_integrity_checker": _binding("responses_only"),
        "race_condition_signal_analyzer": _binding("responses_only"),
        "version_diffing": _binding("responses_only"),
        "role_context_diff": _binding("responses_only", role_context_diff),
        "unauth_access_check": _binding("responses_only"),
        "rate_limit_signal_analyzer": _binding("responses_and_bulk_items"),
        "rate_limit_header_analyzer": _binding("responses_only"),
        "response_size_anomaly_detector": _binding("responses_only"),
        "response_structure_validator": _binding("responses_only", response_structure_validator),
        "payment_flow_intelligence": _binding("responses_only"),
        "payment_provider_detection": _binding("responses_only"),
        "behavior_analysis_layer": _binding("behavior_analysis"),
        "cognitive_flow_analysis": _binding(
            "urls_and_cache",
            run_cognitive_flow_analysis,
            limit_key="cognitive_flow_limit",
            default_limit=12,
        ),
        "redirect_chain_analyzer": _binding("responses_only"),
        "auth_boundary_redirect_detection": _binding("priority_urls_and_cache"),
        "graphql_error_leakage_checker": _binding("responses_only"),
        "openapi_swagger_spec_checker": _binding("urls_and_responses"),
        "ai_endpoint_exposure_analyzer": _binding("urls_and_responses", ai_endpoint_exposure_analyzer),
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
        "json_response_parser": _binding("responses_only", json_response_parser),
        "json_schema_inference": _binding("responses_only", json_schema_inference),
        "cross_tenant_pii_risk_analyzer": _binding(
            "responses_only", cross_tenant_pii_risk_analyzer
        ),
        "server_side_injection_surface_analyzer": _binding(
            "urls_and_responses", server_side_injection_surface_analyzer
        ),
        "options_method_probe": _binding("priority_urls_and_cache"),
        "origin_reflection_probe": _binding("priority_urls_and_cache"),
        "head_method_probe": _binding("priority_urls_and_cache"),
        "cors_preflight_probe": _binding("priority_urls_and_cache"),
        "trace_method_probe": _binding("priority_urls_and_cache"),
        "reflected_xss_probe": _binding(
            "priority_urls_and_cache",
            reflected_xss_probe,
            limit_key="reflected_xss_probe_limit",
            default_limit=6,
        ),
        "sqli_safe_probe": _binding(
            "priority_urls_and_cache",
            sqli_safe_probe,
            limit_key="sqli_probe_limit",
            default_limit=12,
            phase="validate",
            consumes=("priority_urls", "response_cache"),
            produces=("finding",),
        ),
        "graphql_active_probe": _binding("priority_urls_and_cache"),
        "graphql_introspection_check": _binding(
            "priority_urls_and_cache",
            limit_key="graphql_introspection_limit",
            default_limit=10,
        ),
        "http_smuggling_probe": _binding(
            "priority_urls_and_cache",
            limit_key="smuggling_probe_limit",
            default_limit=10,
        ),
        "http2_probe": _binding(
            "priority_urls_and_cache", limit_key="http2_probe_limit", default_limit=8
        ),
        "oauth_flow_analyzer": _binding(
            "priority_urls_and_cache",
            limit_key="oauth_probe_limit",
            default_limit=10,
        ),
        "websocket_message_probe": _binding(
            "priority_urls_and_cache",
            limit_key="websocket_probe_limit",
            default_limit=8,
        ),
        "smart_payload_suggestions": _binding(
            "priority_urls_only",
            context_attr="priority_urls",
            limit_key="payload_suggestion_limit",
            default_limit=18,
            extra_kwargs={},
        ),
        "path_traversal_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="path_traversal_limit",
            default_limit=12,
            runner=path_traversal_active_probe,
        ),
        "command_injection_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="command_injection_limit",
            default_limit=10,
            runner=command_injection_active_probe,
        ),
        "xxe_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="xxe_probe_limit",
            default_limit=8,
            runner=xxe_active_probe,
        ),
        "ssrf_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="ssrf_probe_limit",
            default_limit=10,
            runner=ssrf_active_probe,
        ),
        "proxy_ssrf_probe": _binding(
            "priority_urls_and_cache",
            limit_key="proxy_ssrf_limit",
            default_limit=10,
            runner=proxy_ssrf_probe,
        ),
        "application_ssrf_vector_detector": _binding("responses_only", app_ssrf_scan),
        "open_redirect_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="open_redirect_limit",
            default_limit=10,
            runner=open_redirect_active_probe,
        ),
        "crlf_injection_probe": _binding(
            "priority_urls_and_cache",
            limit_key="crlf_injection_limit",
            default_limit=10,
            runner=crlf_injection_probe,
        ),
        "host_header_injection_probe": _binding(
            "priority_urls_and_cache",
            limit_key="host_header_limit",
            default_limit=8,
            runner=host_header_injection_probe,
        ),
        "ssti_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="ssti_probe_limit",
            default_limit=10,
            runner=ssti_active_probe,
        ),
        "nosql_injection_probe": _binding(
            "priority_urls_and_cache",
            limit_key="nosql_injection_limit",
            default_limit=10,
            runner=nosql_injection_probe,
        ),
        "deserialization_probe": _binding(
            "priority_urls_and_cache",
            limit_key="deserialization_limit",
            default_limit=8,
            runner=deserialization_probe,
        ),
        "dns_record_analyzer": _binding("urls_and_responses"),
        "clickjacking_test": _binding(
            "priority_urls_and_cache",
            limit_key="clickjacking_limit",
            default_limit=20,
        ),
        "ssrf_oob_validator": _binding(
            "urls_and_responses",
            limit_key="ssrf_oob_limit",
            default_limit=15,
            runner=ssrf_oob_validator,
        ),
        "ldap_injection_surface_analyzer": _binding("responses_only"),
        "token_lifetime_analyzer": _binding("responses_only"),
        "mass_assignment_detector": _binding(
            "priority_urls_and_cache",
            limit_key="mass_assignment_limit",
            default_limit=10,
        ),
        "cache_deception_probe": _binding(
            "priority_urls_and_cache",
            limit_key="cache_deception_limit",
            default_limit=12,
        ),
        "email_header_injection_probe": _binding(
            "priority_urls_and_cache",
            limit_key="email_injection_limit",
            default_limit=10,
            runner=email_header_injection_probe,
        ),
        "xml_bomb_detector": _binding(
            "priority_urls_and_cache",
            limit_key="xml_bomb_limit",
            default_limit=8,
            runner=xml_bomb_detector,
        ),
        "deserialization_language_probe": _binding(
            "priority_urls_and_cache",
            limit_key="deserialization_lang_limit",
            default_limit=8,
        ),
        "oauth_misconfiguration_detector": _binding(
            "urls_and_responses", oauth_misconfiguration_detector
        ),
        "xxe_surface_detector": _binding("urls_and_responses", xxe_surface_detector),
        "open_redirect_detector": _binding("urls_and_responses", open_redirect_detector),
        "clickjacking_detector": _binding("urls_and_responses", clickjacking_detector),
        "logging_failure_detector": _binding("urls_and_responses", logging_security_detector),
        "csrf_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="csrf_probe_limit",
            default_limit=10,
            runner=csrf_active_probe,
        ),
        "xpath_injection_probe": _binding(
            "priority_urls_and_cache",
            limit_key="xpath_probe_limit",
            default_limit=10,
            runner=xpath_injection_active_probe,
        ),
        "hpp_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="hpp_probe_limit",
            default_limit=10,
            runner=hpp_active_probe,
        ),
        "jwt_manipulation_probe": _binding(
            "priority_urls_and_cache",
            limit_key="jwt_probe_limit",
            default_limit=10,
            runner=jwt_manipulation_probe,
        ),
        "websocket_hijacking_probe": _binding(
            "priority_urls_and_cache",
            limit_key="websocket_hijack_limit",
            default_limit=10,
            runner=websocket_hijacking_probe,
        ),
        "idor_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="idor_probe_limit",
            default_limit=20,
            runner=idor_active_probe,
        ),
        "file_upload_active_probe": _binding(
            "priority_urls_and_cache",
            limit_key="file_upload_probe_limit",
            default_limit=10,
            runner=file_upload_active_probe,
        ),
        "cookie_manipulation_probe": _binding(
            "priority_urls_and_cache",
            limit_key="cookie_probe_limit",
            default_limit=10,
            runner=cookie_manipulation_probe,
        ),
        "auth_bypass_check": _binding(
            "priority_urls_and_cache",
            limit_key="auth_bypass_limit",
            default_limit=15,
            runner=auth_bypass_check,
        ),
        "tenant_isolation_check": _binding(
            "priority_urls_and_cache",
            limit_key="tenant_isolation_limit",
            default_limit=10,
        ),
        "access_control_analyzer": _binding(
            "priority_urls_and_cache",
            limit_key="access_control_limit",
            default_limit=20,
            runner=access_control_analyzer,
        ),
        "hidden_parameter_miner": _binding(
            "priority_urls_and_cache",
            limit_key="param_mining_limit",
            default_limit=10,
            runner=param_mining_probe,
        ),
        # ---- Modern detection handlers (Fixes A-F) -----------------------
        "js_sink_source_analyzer": _binding(
            "responses_only", src.detection.handlers.js_sink_source_analyzer
        ),
        "wasm_module_introspector": _binding(
            "responses_only", src.detection.handlers.wasm_module_introspector
        ),
        "prototype_pollution_walker": _binding(
            "responses_only", src.detection.handlers.prototype_pollution_walker
        ),
        "dom_runtime_analyzer": _binding(
            "responses_only", src.detection.handlers.dom_runtime_analyzer
        ),
        "waf_fingerprint_analyzer": _binding(
            "responses_only", src.detection.handlers.waf_fingerprint_analyzer
        ),
        "waf_challenge_detector": _binding(
            "responses_only", src.detection.handlers.waf_challenge_detector
        ),
        "csrf_entropy_analyzer": _binding(
            "responses_only", src.detection.handlers.csrf_entropy_analyzer
        ),
        "session_fixation_detector": _binding(
            "responses_only", src.detection.handlers.session_fixation_detector
        ),
        "rate_limit_adaptive_prober": _binding(
            "responses_only", src.detection.handlers.rate_limit_adaptive_prober
        ),
        "race_concurrent_mutator": _binding(
            "responses_only", src.detection.handlers.race_concurrent_mutator
        ),
        # ---- API-specific detection handlers (REST HPP, GraphQL, rate
        # limit diff, JWT claim integrity, WebSocket message security)
        "api_rest_param_pollution": _binding(
            "responses_only", src.detection.handlers.api_rest_param_pollution
        ),
        "api_graphql_introspection": _binding(
            "responses_only", src.detection.handlers.api_graphql_introspection
        ),
        "api_rate_limit_differential": _binding(
            "responses_only", src.detection.handlers.api_rate_limit_differential
        ),
        "api_jwt_claim_integrity": _binding(
            "responses_only", src.detection.handlers.api_jwt_claim_integrity
        ),
        "api_websocket_message_security": _binding(
            "responses_only", src.detection.handlers.api_websocket_message_security
        ),
    }

    for key, binding in bindings.items():
        register_plugin(ANALYZER_BINDING, key)(binding)

    _BINDINGS_REGISTERED = True


def _get_bindings() -> dict[str, AnalyzerBinding]:
    _register_bindings()
    return {reg.key: reg.provider for reg in list_plugins(ANALYZER_BINDING)}


ANALYZER_BINDINGS = _get_bindings()

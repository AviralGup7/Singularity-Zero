from src.pipeline.services.pipeline_orchestrator.stages.active_scan import (
    _load_active_probe_functions,
)


def test_active_scan_import_contract_contains_required_probe_functions() -> None:
    _load_active_probe_functions.cache_clear()
    probes = _load_active_probe_functions()

    required = {
        "run_auth_bypass_probes",
        "command_injection_active_probe",
        "crlf_injection_probe",
        "deserialization_probe",
        "cloud_metadata_active_probe",
        "generate_payload_suggestions",
        "generate_header_payloads",
        "generate_body_payloads",
        "host_header_injection_probe",
        "jwt_token_regex",
        "run_jwt_attack_suite",
        "ldap_injection_active_probe",
        "nosql_injection_probe",
        "open_redirect_active_probe",
        "path_traversal_active_probe",
        "proxy_ssrf_probe",
        "graphql_active_probe",
        "http_smuggling_probe",
        "http2_probe",
        "ssrf_active_probe",
        "ssti_active_probe",
        "state_transition_analyzer",
        "parameter_dependency_tracker",
        "pagination_walker",
        "filter_parameter_fuzzer",
        "response_diff_engine",
        "run_mutation_tests",
        "xss_reflect_probe",
        "xxe_active_probe",
        "xpath_injection_active_probe",
    }
    assert required.issubset(set(probes.keys()))

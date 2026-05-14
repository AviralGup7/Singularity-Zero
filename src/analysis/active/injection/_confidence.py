"""Confidence and severity helpers for active injection probes."""

from src.analysis.helpers._probe_utils import (
    probe_confidence as probe_confidence,
)
from src.analysis.helpers._probe_utils import (
    probe_confidence_from_map,
    probe_severity_from_map,
)
from src.analysis.helpers._probe_utils import (
    probe_severity as probe_severity,
)

__all__ = [
    "PROBE_CONFIDENCE_MAP",
    "PROBE_SEVERITY_MAP",
    "probe_confidence",
    "probe_severity",
    "probe_confidence_from_map",
    "probe_severity_from_map",
]

PROBE_CONFIDENCE_MAP: dict[str, float] = {
    # Path traversal
    "path_traversal_file_read": 0.92,
    "path_traversal_etc_passwd_reflection": 0.95,
    "path_traversal_win_ini_reflection": 0.93,
    "path_traversal_error_pattern": 0.72,
    "path_traversal_path_manipulation": 0.65,
    # Command injection
    "command_injection_output_reflection": 0.94,
    "command_injection_error_pattern": 0.75,
    "command_injection_time_based": 0.80,
    # XXE
    "xxe_file_read": 0.93,
    "xxe_error_reflection": 0.70,
    "xxe_entity_expansion": 0.85,
    # SSRF
    "ssrf_internal_ip_response": 0.90,
    "ssrf_cloud_metadata": 0.95,
    "ssrf_localhost_access": 0.88,
    "ssrf_error_pattern": 0.65,
    # Open redirect
    "open_redirect_location_header": 0.92,
    "open_redirect_body_reflection": 0.78,
    "open_redirect_status_3xx": 0.85,
    # CRLF
    "crlf_header_injection": 0.88,
    "crlf_response_split": 0.90,
    "crlf_set_cookie_injection": 0.92,
    # Host header
    "host_header_reflection_location": 0.85,
    "host_header_reflection_body": 0.72,
    "host_header_password_reset_poison": 0.90,
    # SSTI
    "ssti_arithmetic_reflection": 0.93,
    "ssti_error_pattern": 0.70,
    "ssti_template_syntax": 0.80,
    # NoSQL
    "nosql_auth_bypass": 0.92,
    "nosql_error_pattern": 0.72,
    "nosql_response_divergence": 0.68,
    # Deserialization
    "deserialization_error": 0.82,
    "deserialization_class_reflection": 0.88,
    "deserialization_stack_trace": 0.85,
    # LDAP injection
    "ldap_auth_bypass": 0.92,
    "ldap_error_pattern": 0.75,
    "ldap_info_disclosure": 0.70,
    "ldap_response_divergence": 0.68,
    "ldap_blind_time_based": 0.80,
}

PROBE_SEVERITY_MAP: dict[str, str] = {
    "path_traversal_file_read": "critical",
    "path_traversal_etc_passwd_reflection": "critical",
    "path_traversal_win_ini_reflection": "critical",
    "path_traversal_error_pattern": "high",
    "path_traversal_path_manipulation": "medium",
    "command_injection_output_reflection": "critical",
    "command_injection_error_pattern": "high",
    "command_injection_time_based": "high",
    "xxe_file_read": "critical",
    "xxe_error_reflection": "high",
    "xxe_entity_expansion": "high",
    "ssrf_internal_ip_response": "high",
    "ssrf_cloud_metadata": "critical",
    "ssrf_localhost_access": "high",
    "ssrf_error_pattern": "medium",
    "open_redirect_location_header": "medium",
    "open_redirect_body_reflection": "low",
    "open_redirect_status_3xx": "medium",
    "crlf_header_injection": "high",
    "crlf_response_split": "high",
    "crlf_set_cookie_injection": "high",
    "host_header_reflection_location": "medium",
    "host_header_reflection_body": "low",
    "host_header_password_reset_poison": "high",
    "ssti_arithmetic_reflection": "critical",
    "ssti_error_pattern": "high",
    "ssti_template_syntax": "high",
    "nosql_auth_bypass": "critical",
    "nosql_error_pattern": "high",
    "nosql_response_divergence": "medium",
    "deserialization_error": "high",
    "deserialization_class_reflection": "high",
    "deserialization_stack_trace": "high",
    # LDAP injection
    "ldap_auth_bypass": "critical",
    "ldap_error_pattern": "high",
    "ldap_info_disclosure": "medium",
    "ldap_response_divergence": "medium",
    "ldap_blind_time_based": "high",
}

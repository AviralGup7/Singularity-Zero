"""Shared helper utilities for endpoint classification, signal analysis, and parameter handling.

Provides constants and functions for classifying endpoints, decoding values,
computing confidence scores, building validator results, and analyzing URL patterns.

This package modularizes the helpers into separate files
for better maintainability and AI-agent editability.
"""

# Re-export scoring utilities from helpers_scoring.py
# Re-export probe confidence/severity helpers
# Re-export scoring functions
from src.analysis.helpers.scoring import (
    PARAMETER_WEIGHTS,
    SIGNAL_WEIGHTS,
    normalized_confidence,
    parameter_weight,
    signal_weight,
)

# Re-export classification functions
from ._classification import (
    build_endpoint_meta,
    classify_endpoint,
    decode_candidate_value,
    endpoint_base_key,
    endpoint_signature,
    ensure_endpoint_key,
    filter_noise_urls,
    has_meaningful_parameters,
    is_auth_flow_endpoint,
    is_low_value_endpoint,
    is_noise_url,
    is_self_endpoint,
    is_third_party_auth_host,
    is_tracking_param,
    meaningful_query_pairs,
    resolve_endpoint_key,
    same_host_family,
    strip_tracking_params,
)

# Re-export constants
from ._constants import (
    API_KEY_RE,
    API_PATH_HINTS,
    AUTH_AWARE_PARAMS,
    AUTH_FLOW_PATHS,
    AUTH_PATH_HINTS,
    AUTH_SKIP_PARAMS,
    AWS_KEY_RE,
    DNS_LIKE_RE,
    GITHUB_TOKEN_RE,
    HEX_ONLY_RE,
    HIGH_RISK_LOCATION_ORDER,
    IP_RE,
    JSON_CONTENT_TOKENS,
    JWT_LIKE_RE,
    LOCATION_SEVERITY,
    LONG_ALNUM_RE,
    LOW_VALUE_ENDPOINT_TYPES,
    LOW_VALUE_PATH_HINTS,
    NESTED_REDIRECT_PARAM_NAMES,
    NOISE_FIELD_NAMES,
    REDIRECT_PARAM_NAMES,
    REDIRECT_PATH_HINTS,
    SCHEMA_VERSION,
    SELF_ENDPOINT_HINTS,
    SLACK_TOKEN_RE,
    STATIC_PATH_HINTS,
    STRIPE_KEY_RE,
    THIRD_PARTY_AUTH_HOSTS,
    TRACKING_PARAM_NAMES,
    TRACKING_PARAM_PREFIXES,
    UUID_RE,
)

# Re-export probe confidence/severity helpers
from ._probe_utils import (
    probe_confidence,
    probe_confidence_from_map,
    probe_severity,
    probe_severity_from_map,
)

# Re-export token analysis functions
from ._token_analysis import (
    extract_host_candidate,
    has_remote_scheme,
    is_dangerous_scheme,
    is_internal_host_value,
    is_suspicious_path_redirect,
    looks_like_dns_callback,
    replay_likelihood,
    sort_token_targets,
    token_location_severity,
    token_shape,
)

# Re-export utility functions
from ._utils import (
    build_manual_hint,
    build_validator_result,
    classify_object_family,
    json_type_name,
    normalize_headers,
)

__all__ = [
    "SCHEMA_VERSION",
    "AUTH_PATH_HINTS",
    "STATIC_PATH_HINTS",
    "REDIRECT_PATH_HINTS",
    "API_PATH_HINTS",
    "LOW_VALUE_ENDPOINT_TYPES",
    "TRACKING_PARAM_PREFIXES",
    "TRACKING_PARAM_NAMES",
    "NESTED_REDIRECT_PARAM_NAMES",
    "LOW_VALUE_PATH_HINTS",
    "SELF_ENDPOINT_HINTS",
    "THIRD_PARTY_AUTH_HOSTS",
    "REDIRECT_PARAM_NAMES",
    "NOISE_FIELD_NAMES",
    "AUTH_SKIP_PARAMS",
    "AUTH_AWARE_PARAMS",
    "JSON_CONTENT_TOKENS",
    "SIGNAL_WEIGHTS",
    "PARAMETER_WEIGHTS",
    "HIGH_RISK_LOCATION_ORDER",
    "LOCATION_SEVERITY",
    "API_KEY_RE",
    "AUTH_FLOW_PATHS",
    "AWS_KEY_RE",
    "DNS_LIKE_RE",
    "GITHUB_TOKEN_RE",
    "HEX_ONLY_RE",
    "IP_RE",
    "JWT_LIKE_RE",
    "LONG_ALNUM_RE",
    "SLACK_TOKEN_RE",
    "STRIPE_KEY_RE",
    "UUID_RE",
    "normalized_confidence",
    "parameter_weight",
    "replay_likelihood",
    "signal_weight",
    "sort_token_targets",
    "token_location_severity",
    "token_shape",
    "decode_candidate_value",
    "is_auth_flow_endpoint",
    "classify_endpoint",
    "is_low_value_endpoint",
    "is_self_endpoint",
    "endpoint_signature",
    "endpoint_base_key",
    "strip_tracking_params",
    "meaningful_query_pairs",
    "has_meaningful_parameters",
    "is_tracking_param",
    "is_noise_url",
    "same_host_family",
    "is_third_party_auth_host",
    "extract_host_candidate",
    "is_dangerous_scheme",
    "resolve_endpoint_key",
    "ensure_endpoint_key",
    "has_remote_scheme",
    "json_type_name",
    "normalize_headers",
    "filter_noise_urls",
    "build_endpoint_meta",
    "is_internal_host_value",
    "looks_like_dns_callback",
    "is_suspicious_path_redirect",
    "build_validator_result",
    "build_manual_hint",
    "classify_object_family",
    "probe_confidence",
    "probe_severity",
    "probe_confidence_from_map",
    "probe_severity_from_map",
]

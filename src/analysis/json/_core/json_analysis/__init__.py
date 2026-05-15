"""JSON analysis module for deep inspection of JSON API responses.

Analyzes JSON response bodies for schema inference, sensitive field exposure,
cross-tenant PII risks, role-based access differences, privilege escalation
indicators, and other JSON-specific security patterns.

This package modularizes the JSON analysis into separate files
for better maintainability and AI-agent editability.
"""

# Active probe functions extracted to json/active_probes.py
from src.analysis.json.active_probes import (
    filter_parameter_fuzzer,
    pagination_walker,
)

# Auth-related analysis extracted to json/auth.py
from src.analysis.json.auth import (
    logout_invalidation_check,
    multi_endpoint_auth_consistency_check,
    session_reuse_detection,
    unauth_access_check,
)

# Error-based inference extracted to json/error_probe.py
from src.analysis.json.error_probe import (
    error_based_inference,
)

# Rate limit analysis extracted to json/rate_limit.py
from src.analysis.json.rate_limit import (
    rate_limit_signal_analyzer,
)

# Response size anomaly detection extracted to json/size_anomaly.py
from src.analysis.json.size_anomaly import (
    response_size_anomaly_detector,
)

# Token scope and referer analysis extracted to json/token_scope.py
from src.analysis.json.token_scope import (
    referer_propagation_tracking,
    token_scope_analyzer,
)

# Version diffing extracted to json/version_diff.py
from src.analysis.json.version_diff import (
    version_diffing,
)

# Access boundary tracking and privilege escalation
from ._access_control import (
    access_boundary_tracker,
    privilege_escalation_detector,
)

# Core JSON parsing and schema inference
from ._parsing import (
    cross_tenant_pii_risk_analyzer,
    json_response_parser,
    json_schema_inference,
    nested_object_traversal,
    sensitive_field_detector,
)

# Resource grouping and bulk detection
from ._resource_groups import (
    bulk_endpoint_detector,
    endpoint_resource_groups,
)

# Role context diff and access control
from ._role_diff import (
    cross_user_access_simulation,
    role_based_endpoint_comparison,
    role_context_diff,
)

# Response structure validation
from ._structure_validation import (
    response_structure_validator,
)

__all__ = [
    "access_boundary_tracker",
    "bulk_endpoint_detector",
    "cross_user_access_simulation",
    "endpoint_resource_groups",
    "error_based_inference",
    "filter_parameter_fuzzer",
    "logout_invalidation_check",
    "multi_endpoint_auth_consistency_check",
    "nested_object_traversal",
    "pagination_walker",
    "privilege_escalation_detector",
    "rate_limit_signal_analyzer",
    "referer_propagation_tracking",
    "response_size_anomaly_detector",
    "response_structure_validator",
    "role_based_endpoint_comparison",
    "role_context_diff",
    "session_reuse_detection",
    "token_scope_analyzer",
    "unauth_access_check",
    "version_diffing",
    "json_response_parser",
    "json_schema_inference",
    "sensitive_field_detector",
    "cross_tenant_pii_risk_analyzer",
]

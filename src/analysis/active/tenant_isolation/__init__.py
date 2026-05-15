"""Tenant isolation probe package for multi-tenant SaaS security testing.

Re-exports run_tenant_isolation_probes for backward compatibility with
the original monolithic module.
"""

from .constants import (
    MULTI_TENANT_INDICATORS,
    TENANT_HEADER_NAMES,
    TENANT_PARAM_NAMES,
    TENANT_PATH_PATTERN,
    USER_AGENT,
)
from .detection import _extract_json, _extract_tenant_from_json, detect_tenant_parameters
from .findings import _build_finding
from .http_utils import (
    _build_request_with_tenant_header,
    _build_url_with_tenant,
    _compare_responses,
    _safe_request,
)
from .probes import run_tenant_isolation_probes
from .tests import test_cross_tenant_data_access, test_tenant_isolation, test_vertical_escalation

__all__ = [
    "detect_tenant_parameters",
    "run_tenant_isolation_probes",
    "test_tenant_isolation",
    "test_vertical_escalation",
    "test_cross_tenant_data_access",
    "_build_finding",
    "_safe_request",
    "_build_url_with_tenant",
    "_build_request_with_tenant_header",
    "_compare_responses",
    "_extract_json",
    "_extract_tenant_from_json",
    "TENANT_PARAM_NAMES",
    "TENANT_HEADER_NAMES",
    "TENANT_PATH_PATTERN",
    "MULTI_TENANT_INDICATORS",
    "USER_AGENT",
]

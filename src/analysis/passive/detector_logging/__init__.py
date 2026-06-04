"""Security logging failure detector (backward-compatible shim).

The canonical implementation lives in
``src.analysis.passive.detectors.detector_logging``. This subpackage is
retained for backward compatibility with imports such as
``src.analysis.passive.detector_logging``.
"""

from src.analysis.passive.detectors.detector_logging import (
    logging_security_detector,
)

from ._constants import (
    API_SECRET_PATTERNS,
    DB_CONN_PATTERNS,
    DEBUG_INDICATORS,
    ENV_VAR_PATTERNS,
    FILE_PATH_PATTERNS,
    INTERNAL_IP_PATTERN,
    SENSITIVE_QUERY_PARAMS,
    SENSITIVE_VALUE_PATTERNS,
    SQL_ERROR_PATTERNS,
    STACK_TRACE_PATTERNS,
)
from .detector_logging_helpers import (
    build_finding,
    calculate_risk_score,
    check_api_secrets,
    check_cors_issues,
    check_db_connections,
    check_debug_indicators,
    check_env_vars,
    check_file_paths,
    check_internal_ips,
    check_logging_headers,
    check_sensitive_query_params,
    check_sql_exposure,
    check_stack_traces,
    check_verbose_errors,
    determine_severity,
)  # noqa: F401

logging_failure_detector = logging_security_detector

__all__ = [
    "logging_failure_detector",
    "logging_security_detector",
    "API_SECRET_PATTERNS",
    "DB_CONN_PATTERNS",
    "DEBUG_INDICATORS",
    "ENV_VAR_PATTERNS",
    "FILE_PATH_PATTERNS",
    "INTERNAL_IP_PATTERN",
    "SENSITIVE_QUERY_PARAMS",
    "SENSITIVE_VALUE_PATTERNS",
    "SQL_ERROR_PATTERNS",
    "STACK_TRACE_PATTERNS",
]

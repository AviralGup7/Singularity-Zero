"""Vulnerable and outdated components detector (backward-compatible shim).

The canonical implementation lives in
``src.analysis.passive.detectors.detector_vulnerable_components``. This
subpackage is retained for backward compatibility with imports such as
``src.analysis.passive.detector_vulnerable_components``.
"""

from src.analysis.passive.detectors.detector_vulnerable_components import (
    vulnerable_component_detector,
)

from ._constants import (
    CVE_PATTERNS,
    DEBUG_INDICATORS,
    DEPENDENCY_FILES,
    FRAMEWORK_VERSION_HEADERS,
    KNOWN_VULNERABLE_VERSIONS,
    POWERED_BY_PATTERNS,
    SERVER_VERSION_PATTERNS,
)
from .vulnerable_components_helpers import (
    build_finding,
    calculate_risk_score,
    check_cve_patterns,
    check_debug_indicators,
    check_dependency_disclosure,
    check_framework_headers,
    check_vulnerable_versions,
    determine_severity,
    extract_powered_by_technology,
    extract_server_version,
)  # noqa: F401

__all__ = [
    "vulnerable_component_detector",
    "CVE_PATTERNS",
    "DEBUG_INDICATORS",
    "DEPENDENCY_FILES",
    "FRAMEWORK_VERSION_HEADERS",
    "KNOWN_VULNERABLE_VERSIONS",
    "POWERED_BY_PATTERNS",
    "SERVER_VERSION_PATTERNS",
]

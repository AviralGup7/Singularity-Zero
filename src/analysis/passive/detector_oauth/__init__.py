"""OAuth misconfiguration detector (backward-compatible shim).

The canonical implementation lives in
``src.analysis.passive.detectors.detector_oauth``. This subpackage is
retained for backward compatibility with imports such as
``src.analysis.passive.detector_oauth``.
"""

from src.analysis.passive.detectors.detector_oauth import (
    oauth_misconfiguration_detector,
)

from ._constants import (
    DANGEROUS_SCOPES,
    OAUTH_AUTHZ_PATHS,
    OAUTH_TOKEN_PATHS,
    OAUTH_WELL_KNOWN_PATHS,
    OVERLY_PERMISSIVE_SCOPE_COMBOS,
)
from .detector_oauth_helpers import (
    check_response_oauth_issues,
    check_url_oauth_issues,
    is_oauth_url,
    parse_oauth_params,
)

__all__ = [
    "oauth_misconfiguration_detector",
    "is_oauth_url",
    "parse_oauth_params",
    "check_url_oauth_issues",
    "check_response_oauth_issues",
    "DANGEROUS_SCOPES",
    "OAUTH_AUTHZ_PATHS",
    "OAUTH_TOKEN_PATHS",
    "OAUTH_WELL_KNOWN_PATHS",
    "OVERLY_PERMISSIVE_SCOPE_COMBOS",
]

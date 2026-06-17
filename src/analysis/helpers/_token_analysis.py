"""Token analysis and host/URL utilities.

Re-exports from ``src.core.utils.token_analysis`` for backward compatibility.
"""

from src.core.utils.token_analysis import (  # noqa: F401
    API_KEY_RE,
    AWS_KEY_RE,
    DNS_LIKE_RE,
    GITHUB_TOKEN_RE,
    HEX_ONLY_RE,
    HIGH_RISK_LOCATION_ORDER,
    IP_RE,
    JWT_LIKE_RE,
    LOCATION_SEVERITY,
    LONG_ALNUM_RE,
    SLACK_TOKEN_RE,
    STRIPE_KEY_RE,
    UUID_RE,
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

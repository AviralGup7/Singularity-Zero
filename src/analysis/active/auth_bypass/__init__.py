"""Auth bypass attack probes package.

Provides functions for testing authentication bypass via JWT stripping,
cookie manipulation, and parameter injection.
"""

from .analyzer import run_auth_bypass_probes
from .credential_stuffing import probe_credential_stuffing
from .mfa_bypass import probe_mfa_bypass
from .password_reset_abuse import probe_password_reset_abuse
from .privilege_escalation import probe_privilege_escalation
from .session_fixation import probe_session_fixation
from .token_manipulation import probe_token_manipulation

__all__ = [
    "probe_jwt_stripping",
    "probe_cookie_manipulation",
    "probe_auth_bypass_patterns",
    "run_auth_bypass_probes",
    "probe_token_manipulation",
    "probe_session_fixation",
    "probe_privilege_escalation",
    "probe_credential_stuffing",
    "probe_password_reset_abuse",
    "probe_mfa_bypass",
]

probe_jwt_stripping = probe_token_manipulation
probe_cookie_manipulation = probe_session_fixation
probe_auth_bypass_patterns = probe_privilege_escalation

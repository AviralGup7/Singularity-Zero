"""Orchestrator for auth bypass probes."""

import logging
from typing import Any

from src.analysis.passive.runtime import ResponseCache

from .credential_stuffing import probe_credential_stuffing
from .mfa_bypass import probe_mfa_bypass
from .password_reset_abuse import probe_password_reset_abuse
from .privilege_escalation import probe_privilege_escalation
from .session_fixation import probe_session_fixation
from .token_manipulation import probe_token_manipulation

logger = logging.getLogger(__name__)


def run_auth_bypass_probes(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    config: dict[str, Any] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Main entry point that runs all auth bypass probes.

    Orchestrates JWT stripping, cookie manipulation, and auth bypass
    pattern probes. Returns a dict with results keyed by probe type.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        config: Optional config dict with per-probe limits.

    Returns:
        Dict keyed by probe family, each containing a list of findings.
    """
    config = config or {}
    jwt_limit = int(config.get("jwt_stripping_limit", 12))
    cookie_limit = int(config.get("cookie_manipulation_limit", 12))
    bypass_limit = int(config.get("auth_bypass_limit", 12))
    credential_limit = int(config.get("credential_stuffing_limit", 12))
    mfa_limit = int(config.get("mfa_bypass_limit", 12))
    password_reset_limit = int(config.get("password_reset_abuse_limit", 12))

    logger.info("Running auth bypass probes on %d URLs", len(priority_urls))

    jwt_results = probe_token_manipulation(priority_urls, response_cache, limit=jwt_limit)
    cookie_results = probe_session_fixation(priority_urls, response_cache, limit=cookie_limit)
    bypass_results = probe_privilege_escalation(priority_urls, response_cache, limit=bypass_limit)
    credential_results = probe_credential_stuffing(
        priority_urls,
        response_cache,
        limit=credential_limit,
    )
    mfa_results = probe_mfa_bypass(
        priority_urls,
        response_cache,
        limit=mfa_limit,
    )
    password_reset_results = probe_password_reset_abuse(
        priority_urls,
        response_cache,
        limit=password_reset_limit,
    )

    total = (
        len(jwt_results)
        + len(cookie_results)
        + len(bypass_results)
        + len(credential_results)
        + len(mfa_results)
        + len(password_reset_results)
    )
    logger.info("Auth bypass probes complete: %d total findings", total)

    return {
        "jwt_stripping": jwt_results,
        "cookie_manipulation": cookie_results,
        "auth_bypass_patterns": bypass_results,
        "credential_stuffing": credential_results,
        "mfa_bypass": mfa_results,
        "password_reset_abuse": password_reset_results,
    }

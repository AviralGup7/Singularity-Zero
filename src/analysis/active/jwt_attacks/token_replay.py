"""JWT token replay attack."""

import logging
from typing import Any

from ._helpers import (
    JWT_AUTH_HEADERS,
    _get_original_status,
    _send_with_token,
)

logger = logging.getLogger(__name__)


def test_token_replay(token: str, url: str, session: Any) -> dict[str, Any]:
    """Test JWT token replay vulnerability.

    Tests if a token can be replayed after logout or session termination.
    """
    result: dict[str, Any] = {"attack": "token_replay", "vulnerable": False, "details": []}
    try:
        original_status = _get_original_status(url, session)

        for auth_header in JWT_AUTH_HEADERS:
            resp = _send_with_token(url, token, auth_header, session)
            status = resp.get("status", 0)

            if status == 200 and original_status in (401, 403):
                result["vulnerable"] = True
                result["details"].append(
                    {
                        "auth_header": auth_header,
                        "status_code": status,
                        "original_status": original_status,
                        "finding": "token_replay_accepted",
                    }
                )
                break

        logger.info("Token replay test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("Token replay test error on %s: %s", url, e)
    return result

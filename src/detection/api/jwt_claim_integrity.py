"""JWT claim manipulation / pre-signing integrity detector.

The detection stack already ships an active probe
(``jwt_manipulation_probe``) that fires an alg=none token and a key
confusion token at the target. This module is the *passive* companion
that inspects the JWTs we already see in responses and flags the
manipulation surface that the active probe will then exercise:

* ``alg`` accepted values (``none``, ``HS256`` confused for ``RS256``,
  missing algorithm enforcement, custom ``alg`` tokens).
* Missing / suspicious header fields: ``kid``, ``jku``, ``jwk``, ``x5u``,
  ``x5c``, ``typ``, ``cty``.
* Claim tampering windows before signing (``exp`` in the past,
  ``nbf`` in the future, ``iat`` drifting, ``iss`` / ``aud``
  mismatch, role/scope escalation through the wire format).
* Algorithm-confusion targets: a public-key PEM embedded in the
  ``jwk`` / ``x5c`` header, or a ``kid`` that points to a local file
  (path traversal / SSRF candidates).
* Bypass candidates: ``crit`` header that enables custom mandatory
  processing, missing signature when the verifier is permissive.

The detector is pure-data — it does not call any network endpoints.
The exploitation layer (``headerinjectionengine`` / ``authbypassengine``)
replays the manipulation via the existing JWT active probe.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pattern catalogue
# ---------------------------------------------------------------------------


# Algorithms we want to flag.
_INSECURE_ALGS: frozenset[str] = frozenset(
    {"none", "None", "NONE", "HS1", "RS1"}
)
_SYMMETRIC_ALGS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})
_ASYMMETRIC_ALGS: frozenset[str] = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}
)

# Header fields that, when abused, can lead to bypasses.
_HEADER_INJECTION_FIELDS: tuple[str, ...] = (
    "jku",
    "jwk",
    "x5u",
    "x5c",
    "x5t",
    "x5t#S256",
    "kid",
)

# JWT shape matchers — we accept tokens with and without the signature
# segment, and tolerate the compact serialization only (JWS, not JWE).
_JWT_PATTERN = re.compile(
    r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$"
)
_JWT_NO_SIG_PATTERN = re.compile(r"^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class JWTClaimIntegrityFinding:
    """A single JWT claim integrity finding."""

    url: str
    token_id: str
    header: dict[str, Any]
    payload: dict[str, Any]
    alg: str | None
    findings: tuple[str, ...]
    severity: str
    confidence: float
    summary: str
    remediation_hint: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "indicator": "jwt_claim_manipulation_surface",
            "summary": self.summary,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "token_id": self.token_id,
            "alg": self.alg,
            "header": self.header,
            "payload": self.payload,
            "findings": list(self.findings),
            "remediation_hint": self.remediation_hint,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64_decode(segment: str) -> bytes | None:
    """Decode a JWT base64url segment, tolerating missing padding."""

    if segment is None:
        return None
    text = str(segment).strip()
    if not text:
        return None
    pad = (-len(text)) % 4
    text = text + "=" * pad
    try:
        return base64.urlsafe_b64decode(text)
    except (binascii.Error, ValueError):
        return None


def _parse_token(token: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """Parse a JWT, returning (header, payload, alg)."""

    if not token:
        return None, None, None
    text = token.strip()
    # Strip Bearer prefix.
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    if not _JWT_PATTERN.match(text) and not _JWT_NO_SIG_PATTERN.match(text):
        return None, None, None
    parts = text.split(".")
    if len(parts) < 2:
        return None, None, None
    header_bytes = _b64_decode(parts[0])
    payload_bytes = _b64_decode(parts[1])
    if header_bytes is None or payload_bytes is None:
        return None, None, None
    try:
        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, None, None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None, None, None
    alg_value = header.get("alg")
    alg = str(alg_value) if alg_value is not None else None
    return header, payload, alg


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Claim / header analyzers
# ---------------------------------------------------------------------------


def _is_alg_none(alg: str | None) -> bool:
    if not alg:
        return False
    return alg.lower() == "none"


def _is_pem_payload(value: Any) -> bool:
    return isinstance(value, str) and "BEGIN" in value and "PRIVATE KEY" in value.upper()


def _looks_like_path(value: Any) -> bool:
    return isinstance(value, str) and (
        value.startswith("/")
        or value.startswith("./")
        or value.startswith("..")
        or value.startswith("file:")
        or "://" in value
        or value.startswith("\\")
    )


def _is_expired(payload: dict[str, Any]) -> bool:
    import time

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return False
    return float(exp) < time.time()


def _is_nbf_in_future(payload: dict[str, Any]) -> bool:
    import time

    nbf = payload.get("nbf")
    if not isinstance(nbf, (int, float)):
        return False
    return float(nbf) > time.time() + 30


def _is_iat_drift(payload: dict[str, Any]) -> bool:
    import time

    iat = payload.get("iat")
    if not isinstance(iat, (int, float)):
        return False
    delta = abs(time.time() - float(iat))
    return delta > 365 * 24 * 3600  # > 1 year drift.


def _has_role_escalation(payload: dict[str, Any]) -> tuple[str, ...]:
    escalation: list[str] = []
    for key in ("role", "roles", "scope", "scopes", "groups", "permissions", "admin", "is_admin"):
        value = payload.get(key)
        if isinstance(value, str) and value.lower() in {"admin", "root", "superuser", "*"}:
            escalation.append(f"{key}={value!r}")
        elif isinstance(value, list) and any(
            str(item).lower() in {"admin", "root", "superuser", "*"} for item in value
        ):
            escalation.append(f"{key}={value!r}")
    return tuple(escalation)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------


def analyze_jwt_claim_integrity(
    *,
    url: str,
    token: str,
    expected_alg: str | None = None,
    expected_iss: str | None = None,
    expected_aud: str | None = None,
    extra: dict[str, Any] | None = None,
) -> JWTClaimIntegrityFinding:
    """Analyze a captured JWT and emit a finding.

    Args:
        url: The URL the token was captured from.
        token: The raw JWT (with or without ``Bearer `` prefix).
        expected_alg: Optional algorithm the application is supposed to
            use (e.g. ``RS256``). Mismatches are flagged.
        expected_iss: Optional expected issuer (``iss``) claim.
        expected_aud: Optional expected audience (``aud``) claim.
        extra: Optional extra evidence dict merged into the finding.
    """

    header, payload, alg = _parse_token(token)
    if header is None or payload is None:
        return JWTClaimIntegrityFinding(
            url=url,
            token_id=_short_hash(token or ""),
            header={},
            payload={},
            alg=alg,
            findings=("malformed_token",),
            severity="info",
            confidence=0.20,
            summary=f"Token observed at {url} is not a parseable JWT.",
            evidence=dict(extra or {}),
        )

    findings: list[str] = []
    severity = "info"
    confidence = 0.35

    if _is_alg_none(alg):
        findings.append("alg_none_accepted")
        severity = "critical"
        confidence = max(confidence, 0.95)

    if alg in _INSECURE_ALGS and "alg_none_accepted" not in findings:
        findings.append("insecure_alg")
        severity = "high"
        confidence = max(confidence, 0.85)

    if (
        expected_alg
        and alg
        and expected_alg in _ASYMMETRIC_ALGS
        and alg in _SYMMETRIC_ALGS
    ):
        findings.append("asymmetric_to_symmetric_confusion")
        severity = "critical"
        confidence = max(confidence, 0.90)

    if expected_alg and alg and alg != expected_alg and severity not in {"critical"}:
        findings.append("alg_mismatch")
        severity = "high"
        confidence = max(confidence, 0.75)

    if "kid" in header and _looks_like_path(header["kid"]):
        findings.append("kid_path_traversal_candidate")
        severity = "high"
        confidence = max(confidence, 0.80)
    if "kid" in header and "://" in str(header["kid"]):
        findings.append("kid_ssrf_candidate")
        severity = "high"
        confidence = max(confidence, 0.80)

    if "jku" in header and _looks_like_path(header["jku"]):
        findings.append("jku_external_reference")
        severity = "high"
        confidence = max(confidence, 0.80)
    if "jwk" in header and isinstance(header["jwk"], dict):
        jwk_dict = header["jwk"]
        if jwk_dict.get("kty") in {"oct", "RSA"} and any(
            key in jwk_dict for key in ("p", "q", "d", "k", "n", "e")
        ):
            findings.append("jwk_embedded_key_material")
            severity = "critical"
            confidence = max(confidence, 0.90)
    if "x5c" in header and isinstance(header["x5c"], list):
        for entry in header["x5c"]:
            if _is_pem_payload(entry):
                findings.append("x5c_pem_certificate")
                severity = "high"
                confidence = max(confidence, 0.80)

    if "typ" in header and str(header["typ"]).lower() not in {"jwt", "at+jwt"}:
        findings.append("unusual_typ_header")
        severity = "medium"
        confidence = max(confidence, 0.55)

    if "cty" in header and str(header["cty"]).lower() in {"jwk", "jwk+json"}:
        findings.append("cty_jwk_nested_token")
        severity = "high"
        confidence = max(confidence, 0.80)

    if "crit" in header and isinstance(header["crit"], list) and header["crit"]:
        findings.append("crit_header_extension")
        severity = "high"
        confidence = max(confidence, 0.75)

    if _is_expired(payload):
        findings.append("expired_token_in_use")
        severity = max([severity, "medium"], key=_severity_rank)
        confidence = max(confidence, 0.65)
    if _is_nbf_in_future(payload):
        findings.append("nbf_in_future")
        severity = max([severity, "low"], key=_severity_rank)
        confidence = max(confidence, 0.45)
    if _is_iat_drift(payload):
        findings.append("iat_drift")
        severity = max([severity, "low"], key=_severity_rank)
        confidence = max(confidence, 0.40)

    if expected_iss and str(payload.get("iss", "")) != expected_iss:
        findings.append("iss_mismatch")
        severity = max([severity, "high"], key=_severity_rank)
        confidence = max(confidence, 0.75)

    if expected_aud:
        aud = payload.get("aud")
        if isinstance(aud, str) and aud != expected_aud:
            findings.append("aud_mismatch")
            severity = max([severity, "high"], key=_severity_rank)
            confidence = max(confidence, 0.75)
        elif isinstance(aud, list) and expected_aud not in aud:
            findings.append("aud_mismatch")
            severity = max([severity, "high"], key=_severity_rank)
            confidence = max(confidence, 0.75)

    escalation = _has_role_escalation(payload)
    if escalation:
        findings.append(f"role_escalation_candidate:{';'.join(escalation)}")
        severity = max([severity, "high"], key=_severity_rank)
        confidence = max(confidence, 0.70)

    if not findings:
        findings.append("baseline_review")
        severity = "info"
        confidence = 0.30

    summary = (
        f"JWT manipulation surface at {url} (alg={alg or '?'}): "
        + ", ".join(findings[:3])
    )
    remediation_hint = None
    if severity in {"critical", "high"}:
        remediation_hint = (
            "Enforce a strict allow-list of algorithms server-side "
            "(reject 'none' and HS<->RS confusion); validate 'kid' as "
            "an opaque key identifier, not a URL or path; verify 'iss' "
            "and 'aud' before trusting the claims."
        )

    return JWTClaimIntegrityFinding(
        url=url,
        token_id=_short_hash(token or ""),
        header=header,
        payload=payload,
        alg=alg,
        findings=tuple(findings),
        severity=severity,
        confidence=round(confidence, 3),
        summary=summary,
        remediation_hint=remediation_hint,
        evidence=dict(extra or {}),
    )


def _severity_rank(value: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(value.lower(), 0)


# ---------------------------------------------------------------------------
# Observation adapter
# ---------------------------------------------------------------------------


def jwt_claim_findings_from_observations(
    observations: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert [{url, token, expected_alg, ...}, ...] to findings."""

    findings: list[dict[str, Any]] = []
    for obs in observations:
        url = str(obs.get("url", "")).strip()
        token = obs.get("token") or obs.get("jwt") or obs.get("bearer")
        if not url or not token:
            continue
        finding = analyze_jwt_claim_integrity(
            url=url,
            token=str(token),
            expected_alg=obs.get("expected_alg"),
            expected_iss=obs.get("expected_iss"),
            expected_aud=obs.get("expected_aud"),
            extra=obs.get("extra"),
        )
        findings.append(finding.to_dict())
    return findings


__all__ = [
    "JWTClaimIntegrityFinding",
    "analyze_jwt_claim_integrity",
    "jwt_claim_findings_from_observations",
]

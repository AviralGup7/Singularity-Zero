"""Tests for the JWT claim manipulation / integrity detector."""

import base64
import json

from src.detection.api.jwt_claim_integrity import (
    JWTClaimIntegrityFinding,
    analyze_jwt_claim_integrity,
    jwt_claim_findings_from_observations,
)


def _make_token(header: dict, payload: dict, signature: str = "deadbeef") -> str:
    def _b64(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{_b64(header)}.{_b64(payload)}.{signature}"


def test_alg_none_is_critical() -> None:
    token = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "1"})
    finding = analyze_jwt_claim_integrity(url="https://x", token=token)
    assert isinstance(finding, JWTClaimIntegrityFinding)
    assert "alg_none_accepted" in finding.findings
    assert finding.severity == "critical"
    assert finding.confidence >= 0.9


def test_hs_confusion_with_expected_rs() -> None:
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
    finding = analyze_jwt_claim_integrity(
        url="https://x", token=token, expected_alg="RS256"
    )
    assert "asymmetric_to_symmetric_confusion" in finding.findings
    assert finding.severity == "critical"


def test_alg_mismatch_with_expected_alg() -> None:
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1"})
    finding = analyze_jwt_claim_integrity(
        url="https://x", token=token, expected_alg="HS512"
    )
    assert "alg_mismatch" in finding.findings
    assert finding.severity == "high"


def test_kid_path_traversal_is_high() -> None:
    token = _make_token(
        {"alg": "RS256", "kid": "../../../etc/passwd", "typ": "JWT"},
        {"sub": "1"},
    )
    finding = analyze_jwt_claim_integrity(url="https://x", token=token)
    assert "kid_path_traversal_candidate" in finding.findings
    assert finding.severity == "high"


def test_kid_ssrf_is_high() -> None:
    token = _make_token(
        {"alg": "RS256", "kid": "https://attacker.example/.well-known/jwks.json", "typ": "JWT"},
        {"sub": "1"},
    )
    finding = analyze_jwt_claim_integrity(url="https://x", token=token)
    assert "kid_ssrf_candidate" in finding.findings


def test_jwk_with_private_material_is_critical() -> None:
    token = _make_token(
        {
            "alg": "RS256",
            "jwk": {
                "kty": "RSA",
                "n": "abc",
                "e": "AQAB",
                "d": "private-exponent",
            },
            "typ": "JWT",
        },
        {"sub": "1"},
    )
    finding = analyze_jwt_claim_integrity(url="https://x", token=token)
    assert "jwk_embedded_key_material" in finding.findings
    assert finding.severity == "critical"


def test_role_escalation_is_high() -> None:
    token = _make_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1", "role": "admin", "scopes": ["user", "admin"]},
    )
    finding = analyze_jwt_claim_integrity(url="https://x", token=token)
    assert any("role_escalation_candidate" in f for f in finding.findings)
    assert finding.severity in {"high", "critical"}


def test_expired_token_in_use_is_medium() -> None:
    import time

    token = _make_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1", "exp": int(time.time()) - 600},
    )
    finding = analyze_jwt_claim_integrity(url="https://x", token=token)
    assert "expired_token_in_use" in finding.findings
    assert finding.severity in {"medium", "high", "critical"}


def test_iss_aud_mismatch_is_high() -> None:
    token = _make_token(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1", "iss": "attacker", "aud": "other"},
    )
    finding = analyze_jwt_claim_integrity(
        url="https://x", token=token, expected_iss="victim", expected_aud="victim"
    )
    assert "iss_mismatch" in finding.findings
    assert "aud_mismatch" in finding.findings
    assert finding.severity in {"high", "critical"}


def test_crit_header_is_high() -> None:
    token = _make_token(
        {"alg": "RS256", "crit": ["exp"], "typ": "JWT"},
        {"sub": "1"},
    )
    finding = analyze_jwt_claim_integrity(url="https://x", token=token)
    assert "crit_header_extension" in finding.findings
    assert finding.severity == "high"


def test_malformed_token_is_info() -> None:
    finding = analyze_jwt_claim_integrity(url="https://x", token="not-a-jwt")
    assert "malformed_token" in finding.findings
    assert finding.severity == "info"


def test_bearer_prefix_is_stripped() -> None:
    token = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "1"})
    finding = analyze_jwt_claim_integrity(url="https://x", token=f"Bearer {token}")
    assert "alg_none_accepted" in finding.findings


def test_observation_adapter_handles_optional_fields() -> None:
    none_token = _make_token(
        {"alg": "none", "typ": "JWT"},
        {"sub": "1"},
    )
    hs_token = _make_token(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1"},
    )
    findings = jwt_claim_findings_from_observations(
        [
            {"url": "https://x", "token": none_token, "expected_alg": "RS256"},
            {"url": "https://y", "token": ""},
            {"url": "https://z", "token": hs_token, "expected_alg": "RS256"},
        ]
    )
    assert len(findings) == 2
    assert "alg_none_accepted" in findings[0]["findings"]
    assert "asymmetric_to_symmetric_confusion" in findings[1]["findings"]

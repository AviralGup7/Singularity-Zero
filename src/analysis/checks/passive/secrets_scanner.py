"""Passive secrets scanner for API security testing.

Inspects HTTP response headers, bodies, and raw content for hardcoded
secrets using a library of regex patterns.  Returns
``PassiveFinding``-shaped results that are compatible with the
existing analysis pipeline.  No optional dependencies are required
— stdlib only (``re``, ``base64``, ``json``, ``hashlib``).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key ID"),
    ("aws_secret_key", re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]"), "AWS secret key"),
    ("github_token", re.compile(r"\bghp_[0-9a-zA-Z]{36}\b"), "GitHub personal access token"),
    ("github_oauth", re.compile(r"\bgho_[0-9a-zA-Z]{36}\b"), "GitHub OAuth token"),
    ("github_app_token", re.compile(r"\bghs_[0-9a-zA-Z]{36}\b"), "GitHub app token"),
    ("google_api_key", re.compile(r"\bAIzaSy[0-9a-zA-Z_-]{33}\b"), "Google API key"),
    ("heroku_api_key", re.compile(r"(?i)heroku(.{0,20})?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "Heroku API key"),
    ("generic_bearer", re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"), "Bearer token in Authorization header"),
    ("api_key_header", re.compile(r"(?i)(api[-_]?key|apikey|api[-_]?secret)\s*[:=]\s*['\"]([^'\"]+)['\"]"), "API key in header or body"),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b"), "JSON Web Token (JWT)"),
    ("private_rsa_key", re.compile(r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----"), "RSA private key PEM block"),
    ("private_ec_key", re.compile(r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"), "EC private key PEM block"),
    ("private_pkcs8_key", re.compile(r"-----BEGIN\s+PRIVATE\s+KEY-----"), "PKCS#8 private key PEM block"),
    ("database_url", re.compile(r"(?i)(postgresql|mysql|mongodb|redis|mssql)://[^:]+:[^@]+@[^/]+"), "Database connection string with credentials"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z-]+"), "Slack token"),
    ("twilio_sid", re.compile(r"\bSK[a-f0-9]{32}\b"), "Twilio account SID"),
    ("password_in_body", re.compile(r'(?i)"password"\s*:\s*"[^"\n]{3,}"'), "Password field in response body"),
    ("oauth_token", re.compile(r"\b[0-9a-f]{32,}\b"), "Potential OAuth token (32+ hex chars)"),
    ("encrypted_jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{20,}"), "Encoded JWT header segment"),
    ("base64_blob", re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "Base64-encoded blob (potential secret)"),
)


@dataclass(frozen=True, slots=True)
class SecretFinding:
    """A single secret detected in a response."""

    category: str
    pattern_name: str
    secret_type: str
    url: str
    location: str
    matched_value: str
    confidence: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "pattern_name": self.pattern_name,
            "secret_type": self.secret_type,
            "url": self.url,
            "location": self.location,
            "matched_value": self._redacted(),
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    def _redacted(self) -> str:
        value = self.matched_value
        if len(value) <= 8:
            return value[:2] + "***"
        return f"{value[:4]}...{value[-4:]}"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def scan_response(
    url: str,
    headers: dict[str, str] | None = None,
    body: str | bytes | None = None,
    *,
    location_hint: str = "body",
) -> list[SecretFinding]:
    """Scan a single response for hardcoded secrets.

    Run this as a passive check after a scan step resolves a URL.
    """
    findings: list[SecretFinding] = []
    text_body = ""
    if isinstance(body, bytes):
        text_body = body.decode("utf-8", errors="replace")
    elif body is not None:
        text_body = str(body)

    corpus_parts: dict[str, str] = {}
    if headers:
        header_chunk = "\n".join(f"{k}: {v}" for k, v in headers.items())
        corpus_parts["headers"] = header_chunk
    if text_body:
        corpus_parts["body"] = text_body

    for pattern_name, pattern, secret_type in _PATTERNS:
        for loc, corpus in corpus_parts.items():
            for match in pattern.finditer(corpus):
                matched_value = match.group(0)
                findings.append(
                    SecretFinding(
                        category="exposed_secret",
                        pattern_name=pattern_name,
                        secret_type=secret_type,
                        url=url,
                        location=f"{location_hint}:{loc}",
                        matched_value=matched_value,
                        confidence=_confidence_for(pattern_name, matched_value),
                        metadata={"fingerprint": _fingerprint(matched_value)},
                    )
                )

    return _dedupe(findings)


def _confidence_for(pattern_name: str, value: str) -> str:
    high_confidence_prefixes = ("AKIA", "ghp_", "gho_", "ghs_", "AIzaSy", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "SK", "eyJ")
    medium_confidence_prefixes = ("-----BEGIN",)
    if any(value.startswith(prefix) for prefix in high_confidence_prefixes):
        return "high"
    if any(pattern_name.startswith(prefix) for prefix in medium_confidence_prefixes):
        return "medium"
    return "low"


def _dedupe(findings: list[SecretFinding]) -> list[SecretFinding]:
    seen: set[tuple[str, str]] = set()
    out: list[SecretFinding] = []
    for finding in findings:
        key = (finding.pattern_name, finding._fingerprint(finding.matched_value) if hasattr(finding, "_fingerprint") else finding.matched_value)
        fp = finding.metadata.get("fingerprint") or hashlib.sha256(finding.matched_value.encode()).hexdigest()[:16]
        key = (finding.pattern_name, fp)
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return out


def _fingerprint(self, value: str) -> str:  # pragma: no cover - helper
    return hashlib.sha256(value.encode()).hexdigest()[:16]


SecretFinding._fingerprint = _fingerprint  # type: ignore[attr-defined]


__all__ = ["SecretFinding", "scan_response"]

"""WAF fingerprint detector.

Inspects a captured HTTP response (headers + body preview) and identifies
the WAF/CDN vendor with confidence scoring. The output is consumed by the
challenge detector and the bypass strategies module.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from src.detection.waf.fingerprints import (
    BY_NAME,
    CATALOGUE,
    WAFFingerprint,
    to_dict,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class WAFMatch:
    fingerprint: WAFFingerprint
    confidence: float
    matched_signals: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.fingerprint.name,
            "vendor": self.fingerprint.vendor,
            "category": self.fingerprint.category,
            "confidence": round(self.confidence, 3),
            "matched_signals": list(self.matched_signals),
            "bypass_strategies": list(self.fingerprint.bypass_strategies),
        }


def _lower_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {str(k).lower(): str(v).lower() for k, v in headers.items() if k is not None}


def fingerprint_response(
    headers: Mapping[str, str] | None,
    body: str | bytes | None = None,
    *,
    cookies: Mapping[str, str] | None = None,
) -> WAFMatch:
    """Identify the WAF/CDN that produced the response.

    Returns a `WAFMatch` with the best candidate and its confidence.
    """

    if isinstance(body, bytes):
        try:
            body_text = body.decode("utf-8", errors="ignore").lower()
        except Exception:  # pragma: no cover
            body_text = ""
    elif isinstance(body, str):
        body_text = body.lower()
    else:
        body_text = ""

    headers_lower = _lower_headers(headers)
    cookie_str = " ".join(str(v).lower() for v in (cookies or {}).values()) if cookies else ""
    cookie_str = cookie_str.lower()
    server_header = headers_lower.get("server", "") + " " + headers_lower.get("via", "")

    best: WAFMatch | None = None

    for fp in CATALOGUE:
        matched: list[str] = []
        score = 0.0

        for header in fp.headers:
            if header.lower() in headers_lower:
                score += 0.20
                matched.append(f"header:{header}")

        for token in fp.server_tokens:
            if token and token in server_header:
                score += 0.25
                matched.append(f"server:{token}")

        for cookie in fp.cookies:
            if cookie_str and cookie in cookie_str:
                score += 0.20
                matched.append(f"cookie:{cookie}")

        for marker in fp.body_signals:
            if marker and marker in body_text:
                score += 0.20
                matched.append(f"body:{marker}")

        for marker in fp.challenge_markers:
            if marker and marker in body_text:
                score += 0.30
                matched.append(f"challenge:{marker}")

        if score <= 0:
            continue
        # Cap at 0.99
        score = min(score, 0.99)
        match = WAFMatch(
            fingerprint=fp,
            confidence=score,
            matched_signals=tuple(matched),
        )
        if best is None or match.confidence > best.confidence:
            best = match

    if best is None or best.confidence == 0.0:
        return None

    return best


def fingerprint_to_finding(match: WAFMatch, *, url: str) -> dict[str, Any]:
    """Convert a WAFMatch into a finding dict consumable by the runtime."""

    return {
        "url": url,
        "indicator": "waf_fingerprint",
        "summary": f"WAF/CDN detected: {match.fingerprint.name}",
        "severity": "info",
        "confidence": round(match.confidence, 3),
        "waf_name": match.fingerprint.name,
        "waf_vendor": match.fingerprint.vendor,
        "waf_category": match.fingerprint.category,
        "matched_signals": list(match.matched_signals),
        "bypass_strategies": list(match.fingerprint.bypass_strategies),
        "fingerprint": to_dict(match.fingerprint),
    }


def identify_candidates(
    headers: Mapping[str, str] | None,
    body: str | bytes | None = None,
    *,
    cookies: Mapping[str, str] | None = None,
) -> list[WAFMatch]:
    """Return all candidates whose score is non-zero, ordered by confidence."""

    if isinstance(body, bytes):
        body_text = body.decode("utf-8", errors="ignore").lower()
    elif isinstance(body, str):
        body_text = body.lower()
    else:
        body_text = ""

    headers_lower = _lower_headers(headers)
    cookie_str = " ".join(str(v).lower() for v in (cookies or {}).values()) if cookies else ""
    cookie_str = cookie_str.lower()
    server_header = headers_lower.get("server", "") + " " + headers_lower.get("via", "")

    matches: list[WAFMatch] = []
    for fp in CATALOGUE:
        matched: list[str] = []
        score = 0.0
        for header in fp.headers:
            if header.lower() in headers_lower:
                score += 0.20
                matched.append(f"header:{header}")
        for token in fp.server_tokens:
            if token and token in server_header:
                score += 0.25
                matched.append(f"server:{token}")
        for cookie in fp.cookies:
            if cookie_str and cookie in cookie_str:
                score += 0.20
                matched.append(f"cookie:{cookie}")
        for marker in fp.body_signals:
            if marker and marker in body_text:
                score += 0.20
                matched.append(f"body:{marker}")
        for marker in fp.challenge_markers:
            if marker and marker in body_text:
                score += 0.30
                matched.append(f"challenge:{marker}")
        if score <= 0:
            continue
        matches.append(
            WAFMatch(
                fingerprint=fp,
                confidence=min(score, 0.99),
                matched_signals=tuple(matched),
            )
        )
    matches.sort(key=lambda m: m.confidence, reverse=True)
    return matches


__all__ = [
    "WAFMatch",
    "fingerprint_response",
    "fingerprint_to_finding",
    "identify_candidates",
    "BY_NAME",
    "CATALOGUE",
]

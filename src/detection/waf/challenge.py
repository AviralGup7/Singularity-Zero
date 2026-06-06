"""WAF challenge-page detector.

Modern WAFs (Cloudflare Turnstile, Akamai Bot Manager, Imperva hCaptcha)
return 200 OK with a challenge page body rather than a 403. The naive
``baseline vs injected header`` Content-Length delta heuristic on the
header-injection engine would falsely flag these as bypasses.

This module classifies a captured response as a challenge page (or not)
and exposes helpers that the header-injection engine uses to suppress
false positives and to choose follow-up bypass strategies.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from src.detection.waf.fingerprints import BY_NAME, CATALOGUE, GENERIC, WAFFingerprint

logger = logging.getLogger(__name__)


# (regex, label, weight)
_BODY_CHALLENGE_PATTERNS: tuple[tuple[str, str, float], ...] = (
    (r"cf-chl-bypass", "cloudflare_challenge_script", 0.7),
    (r"cf-challenge", "cloudflare_challenge", 0.7),
    (r"checking your browser before accessing", "cloudflare_browser_check", 0.6),
    (r"please enable cookies", "cookie_required", 0.4),
    (r"attention required! \| cloudflare", "cloudflare_attention", 0.7),
    (r"akamai bot manager", "akamai_bot_manager", 0.7),
    (r"akamai challenge", "akamai_challenge", 0.6),
    (r"data-sitekey=[\"']?[A-Za-z0-9_-]{20,}", "captcha_sitekey", 0.5),
    (r"<title>.*?(?:are you human|captcha|verify|robot).*?</title>", "title_challenge", 0.4),
    (r"<form[^>]*action=[\"'][^\"']*challenge", "challenge_form", 0.5),
    (r"hcaptcha|turnstile|recaptcha", "captcha_widget", 0.6),
    (r"awswaf|aws-waf-token", "aws_waf_token", 0.7),
    (r"imperva incident", "imperva_incident", 0.6),
    (r"wallarm-challenge", "wallarm_challenge", 0.6),
    (r"x-amzn-errortype", "aws_error", 0.3),
    (r"<noscript>.*?(?:enable javascript|javascript is required).*?</noscript>", "js_required", 0.4),
)


# Status codes returned by challenge pages.
_CHALLENGE_STATUS_CODES: frozenset[int] = frozenset({200, 202, 403, 406, 409, 429, 503})


@dataclass(slots=True)
class ChallengeAssessment:
    is_challenge: bool
    confidence: float
    challenge_type: str | None
    matched_patterns: tuple[str, ...]
    waf_match: WAFFingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_challenge": self.is_challenge,
            "confidence": round(self.confidence, 3),
            "challenge_type": self.challenge_type,
            "matched_patterns": list(self.matched_patterns),
            "waf_name": self.waf_match.name,
        }


def _lower_body(body: str | bytes | None) -> str:
    if body is None:
        return ""
    if isinstance(body, bytes):
        try:
            return body.decode("utf-8", errors="ignore").lower()
        except Exception:  # pragma: no cover
            return ""
    if isinstance(body, str):
        return body.lower()
    return ""


def detect_challenge(
    headers: Mapping[str, str] | None,
    body: str | bytes | None,
    *,
    status_code: int | None = None,
) -> ChallengeAssessment:
    """Classify a response as a challenge page or not."""

    body_text = _lower_body(body)
    headers_lower = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items() if k}
    server = headers_lower.get("server", "") + " " + headers_lower.get("via", "")
    cookie_header = headers_lower.get("set-cookie", "")
    cookies_lower = cookie_header.lower()

    waf_match: WAFFingerprint = GENERIC
    waf_score = 0.0
    matched: list[str] = []
    score = 0.0
    challenge_type: str | None = None

    for fp in CATALOGUE:
        local = 0.0
        for marker in fp.challenge_markers:
            if marker and marker in body_text:
                local += 0.30
                matched.append(f"challenge:{marker}")
        for marker in fp.body_signals:
            if marker and marker in body_text:
                local += 0.20
                matched.append(f"body:{marker}")
        for cookie in fp.cookies:
            if cookie and cookie in cookies_lower:
                local += 0.20
                matched.append(f"cookie:{cookie}")
        for header in fp.headers:
            if header.lower() in headers_lower:
                local += 0.15
                matched.append(f"header:{header}")
        for token in fp.server_tokens:
            if token and token in server:
                local += 0.20
                matched.append(f"server:{token}")
        if local > waf_score:
            waf_score = local
            waf_match = fp

    for pattern, label, weight in _BODY_CHALLENGE_PATTERNS:
        if re.search(pattern, body_text, re.IGNORECASE | re.DOTALL):
            score += weight
            matched.append(label)
            challenge_type = label

    # Status code heuristic — challenge pages often return 200 or 403
    if status_code is not None and status_code in _CHALLENGE_STATUS_CODES:
        if score >= 0.30:
            score += 0.10

    # Heuristic: tiny bodies (< 4 KB) with a JS challenge script
    if 0 < len(body_text) < 4096 and any(
        token in body_text for token in ("var a=function()", "setTimeout(function()", "pow(", "BigInteger")
    ):
        score += 0.40
        matched.append("body:js_arithmetic_challenge")
        if not challenge_type:
            challenge_type = "js_arithmetic_challenge"

    score = min(score, 0.99)
    is_challenge = score >= 0.50

    if waf_match is GENERIC and score >= 0.4:
        # Try header-based identification
        for fp in CATALOGUE:
            if any(header.lower() in headers_lower for header in fp.headers):
                waf_match = fp
                matched.append(f"waf_promoted:{fp.name}")
                break

    return ChallengeAssessment(
        is_challenge=is_challenge,
        confidence=score,
        challenge_type=challenge_type,
        matched_patterns=tuple(matched),
        waf_match=waf_match,
    )


def is_challenge_response(
    headers: Mapping[str, str] | None,
    body: str | bytes | None,
    *,
    status_code: int | None = None,
) -> bool:
    """Fast boolean wrapper around `detect_challenge`."""

    return detect_challenge(headers, body, status_code=status_code).is_challenge


def assess_for_engine(
    headers: Mapping[str, str] | None,
    body: str | bytes | None,
    *,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Return a small dict the HeaderInjectionEngine can attach to results."""

    assessment = detect_challenge(headers, body, status_code=status_code)
    payload = assessment.to_dict()
    payload["bypass_strategies"] = list(assessment.waf_match.bypass_strategies)
    return payload


__all__ = [
    "ChallengeAssessment",
    "assess_for_engine",
    "detect_challenge",
    "is_challenge_response",
    "BY_NAME",
]

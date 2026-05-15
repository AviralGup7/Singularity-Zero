"""WAF detection for active scanning.

Signature-based WAF detection using response analysis. Inspired by
XSStrike's wafDetector but rewritten for our pipeline architecture.

Detects common WAF products by injecting a noisy payload and matching
response characteristics (status codes, headers, body patterns) against
known WAF signatures.

Usage::

    detector = WafDetector()
    waf_name = detector.detect(url, params, headers)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Known WAF signatures: name -> {page, code, headers, vendor}
# Each field is a regex pattern (string) or None.
WAF_SIGNATURES: dict[str, dict[str, str | None]] = {
    "Cloudflare": {
        "page": r"(?i)cloudflare.*ray|cf-cache-status|cf-request-id|ray id",
        "code": r"40[39]",
        "headers": r"cf-ray|cf-cache-status|cf-request-id",
    },
    "Akamai": {
        "page": r"(?i)akamaighost.*rejected",
        "code": r"40[36]",
        "headers": r"server.*akamai|x-akamai-transformed",
    },
    "AWS WAF": {
        "page": None,
        "code": r"403",
        "headers": r"x-amzn-requestid|x-amzn-waf-action",
    },
    "ModSecurity": {
        "page": r"(?i)(?:ModSecurity|mod_security|blocked by mod_security)",
        "code": r"40[36]",
        "headers": r"ModSecurity",
    },
    "Sucuri": {
        "page": r"(?i)sucuri.*cloudproxy",
        "code": r"403",
        "headers": r"x-sucuri-id|x-sucuri-cache",
    },
    "Imperva": {
        "page": r"(?i)(?:imperva|incapsula|visiting from)",
        "code": r"40[36]",
        "headers": r"x-iinfo|x-cdn|incap_ses|visid_incap",
    },
    "Barracuda": {
        "page": r"(?i)barracuda",
        "code": None,
        "headers": r"barra_counter_session|barracuda_",
    },
    "F5 BIG-IP": {
        "page": None,
        "code": None,
        "headers": r"F5-|X-WA-Info|X-Cnection",
    },
    "FortiWeb": {
        "page": r"(?i)fortiweb",
        "code": r"403",
        "headers": r"FortiWeb",
    },
    "DenyAll": {
        "page": r"(?i)(?:denied|sessioncookie)",
        "code": None,
        "headers": r"sessioncookie",
    },
    "Dot Defender": {
        "page": r"(?i)sitelock",
        "code": None,
        "headers": None,
    },
    "NSFocus": {
        "page": None,
        "code": r"405",
        "headers": r"NSFocus",
    },
    "Palo Alto": {
        "page": r"(?i)paloalto",
        "code": r"40[34]",
        "headers": None,
    },
    "Radware": {
        "page": r"(?i)radware",
        "code": None,
        "headers": r"X-SL-CompState",
    },
    "Safe3": {
        "page": r"(?i)safedog",
        "code": None,
        "headers": r"Safe3|safedog",
    },
    "Comodo": {
        "page": None,
        "code": None,
        "headers": r"Protected by COMODO WAF",
    },
    "Yundun": {
        "page": r"(?i)yunda|yunsuo",
        "code": None,
        "headers": r"yundun|yunsuo",
    },
    "Qiniu CDN": {
        "page": None,
        "code": None,
        "headers": r"X-Qiniu-CDN",
    },
}


@dataclass
class WafDetectionResult:
    """Result of a WAF detection attempt."""

    detected: bool
    waf_name: str | None = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        if self.detected:
            return f"WAF detected: {self.waf_name} (confidence: {self.confidence:.0%})"
        return "No WAF detected"


class WafDetector:
    """WAF detection engine."""

    def __init__(self, noise_payload: str = '<script>alert("XSS")</script>') -> None:
        self._noise = noise_payload

    def detect_from_response(
        self,
        url: str,
        status_code: int,
        response_body: str,
        response_headers: dict[str, str],
        triggered_by_injection: bool = True,
    ) -> WafDetectionResult:
        """Detect WAF presence from an existing HTTP response.

        This is the non-intrusive variant: analyzes the provided response
        without sending additional requests.

        Args:
            url: Target URL (unused in passive analysis).
            status_code: HTTP status code.
            response_body: Response body text.
            response_headers: Response headers dict.
            triggered_by_injection: Whether the response was triggered by
                a potentially malicious payload injection.

        Returns:
            WafDetectionResult with detection status, WAF name, and confidence.
        """
        best_match: tuple[float, str | None, list[str]] = (0.0, None, [])

        for waf_name, signature in WAF_SIGNATURES.items():
            score = 0.0
            evidence: list[str] = []

            page_pattern = signature.get("page")
            code_pattern = signature.get("code")
            headers_pattern = signature.get("headers")

            if page_pattern and re.search(page_pattern, response_body, re.I):
                score += 1.0
                evidence.append(f"body matches '{waf_name}' signature")

            if code_pattern and re.search(code_pattern, str(status_code), re.I):
                score += 0.5
                evidence.append(f"status code {status_code} matches")

            if headers_pattern:
                header_str = "\n".join(f"{k}: {v}" for k, v in response_headers.items())
                if re.search(headers_pattern, header_str, re.I):
                    score += 1.0
                    evidence.append(f"header matches '{waf_name}' signature")

            if score > best_match[0]:
                best_match = (score, waf_name, evidence)

        best_score, best_name, best_evidence = best_match
        confidence = min(1.0, best_score / 2.5) if triggered_by_injection else 0.0

        # Only report detection if triggered error response AND confidence > threshold
        if triggered_by_injection and status_code >= 400 and best_score > 0:
            detected = True
        elif not triggered_by_injection and best_score >= 2.0:
            detected = True
        else:
            detected = False

        return WafDetectionResult(
            detected=detected,
            waf_name=best_name,
            confidence=confidence,
            evidence=best_evidence,
        )

    def detect(
        self,
        url: str,
        params: dict[str, str],
        headers: dict[str, str],
        method: str = "GET",
        http_client: Any = None,
        timeout: int = 10,
    ) -> WafDetectionResult:
        """Active WAF detection by injecting a noisy payload.

        Args:
            url: Target URL.
            params: Query/body parameters.
            headers: Request headers.
            method: HTTP method.
            http_client: Session-like object with .request() method.
            timeout: Request timeout in seconds.

        Returns:
            WafDetectionResult with detection status.
        """
        if http_client is None:
            return WafDetectionResult(detected=False)

        injection_params = dict(params)
        injection_params["waf_test"] = self._noise

        try:
            if method.upper() == "GET":
                resp = http_client.get(
                    url,
                    params=injection_params,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                )
            else:
                resp = http_client.post(
                    url,
                    data=injection_params,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                )

            return self.detect_from_response(
                url=url,
                status_code=resp.status_code,
                response_body=resp.text,
                response_headers=dict(resp.headers),
                triggered_by_injection=True,
            )
        except Exception as exc:
            logger.debug("WAF detection request failed for %s: %s", url, exc)
            return WafDetectionResult(detected=False)

"""
Cyber Security Test Pipeline - Polymorphic Request Engine
Implements real-time fingerprint mutation for WAF and behavioral evasion.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from src.core.frontier.chameleon_evasion import (
    ChameleonEvasionEngine,
    JA3FingerprintModel,
    TimingPermutator,
)
from src.core.logging.trace_logging import get_pipeline_logger
from src.execution.active_manifest import ActiveCapability, query_active_manifests

logger = get_pipeline_logger(__name__)


def _title_header(key: str) -> str:
    """Correctly title-case an HTTP header key (e.g. 'accept-encoding' -> 'Accept-Encoding')."""
    return "-".join(word.capitalize() for word in key.split("-"))


class RequestChameleon:
    """
    Frontier Evasion Engine.
    Mutates request characteristics (header order, capitalization, padding)
    to prevent fingerprinting by modern WAFs and bot-management systems.
    """

    # Fix #201: Expanded UA pool to 20+ realistic entries for better evasion coverage.
    _USER_AGENTS: list[str] = [
        # Chrome - Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        # Chrome - macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        # Chrome - Linux
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        # Firefox - Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        # Firefox - macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
        # Firefox - Linux
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        # Safari - macOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Safari - iPhone
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
        # Edge - Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
        # Samsung Browser
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36",
        # Opera
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
        # Brave
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/1.65.0",
    ]

    # JA3 Signatures for TLS fingerprinting (Chrome, Firefox, Safari on various OSs)
    # Format: SSLVersion,Cipher,Extensions,EllipticCurves,EllipticCurveFormats
    _JA3_SIGNATURES: list[str] = [
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49201-49172-49202-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
        "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49161-49162-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0",
    ]

    def __init__(self) -> None:
        # Instance copy so subclasses can override without touching class variable
        self._user_agents = list(self._USER_AGENTS)
        self._ja3_signatures = list(self._JA3_SIGNATURES)
        self._evasion_engine = ChameleonEvasionEngine()
        self._timing = TimingPermutator()
        self._ja3 = JA3FingerprintModel()

    def get_metrics(self) -> dict[str, Any]:
        """Query current metrics from the evasion engine."""
        return self._evasion_engine.get_metrics()

    def reset_metrics(self) -> None:
        """Reset metrics in the evasion engine."""
        self._evasion_engine.reset_metrics()

    def detect_waf(
        self,
        headers: dict[str, str],
        body: str,
        cookies: dict[str, str] | None = None,
    ) -> str | None:
        """
        Identify active WAF based on response headers, cookies, and body patterns.
        Utilizes CDN_WAF_PATTERNS.
        """
        try:
            from src.core.frontier.waf_patterns import CDN_WAF_PATTERNS
        except ImportError:
            return None

        headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
        cookies_lower = {k.lower(): str(v).lower() for k, v in (cookies or {}).items()}
        body_lower = (body or "").lower()

        best_provider = None
        best_score = 0

        for provider, patterns in CDN_WAF_PATTERNS.items():
            score = 0
            # Check headers
            for pattern in patterns.get("headers", []):
                pattern_lower = pattern.lower()
                for k, v in headers_lower.items():
                    if pattern_lower in k or pattern_lower in v:
                        score += 1

            # Check cookies
            for pattern in patterns.get("cookies", []):
                if pattern.lower() in cookies_lower:
                    score += 1

            # Check body
            for pattern in patterns.get("body", []):
                if pattern.lower() in body_lower:
                    score += 1

            if score > best_score:
                best_score = score
                best_provider = provider

        return best_provider

    def mutate_headers(self, base_headers: dict[str, str]) -> dict[str, str]:
        """
        Create a polymorphic header set with randomized order and correct casing.
        Fix #202: Use secrets.choice for cryptographically random UA selection.
        Fix #203: Use _title_header() for correct HTTP header title casing.
        """
        headers: dict[str, str] = {}

        # 1. Randomize User-Agent from pool using cryptographic PRNG
        ua = secrets.choice(self._user_agents)
        headers["User-Agent"] = ua

        # 2. Randomize Casing (some WAFs look for static lowercase)
        for k, v in base_headers.items():
            if k.lower() == "user-agent":
                continue

            new_key = k
            # Use cryptographically random coin flip
            if secrets.randbelow(2):
                # Fix #203: Use proper HTTP header title casing
                new_key = _title_header(k)

            headers[new_key] = v

        # 3. Inject Polymorphic Noise headers
        noise_chance = 6  # Default ~30% chance (secrets.randbelow(10) > 6)
        try:
            from src.learning.integration import LearningIntegration

            learning = LearningIntegration.get_or_create()
            if learning and learning.config.enabled:
                try:
                    active_patterns = [
                        p.to_db_row() for p in learning._fp_tracker._cache.values() if p.is_active
                    ]
                except Exception:
                    active_patterns = []

                if any(
                    p.get("category") in ("waf_block", "rate_limit", "cdn_error")
                    for p in active_patterns
                ):
                    noise_chance = 0  # Increase to 90% chance (secrets.randbelow(10) > 0)
        except Exception as e:
            logger.debug("Chameleon noise adaptation skipped: %s", e)

        if secrets.randbelow(10) > noise_chance:
            noise_prefixes = [
                "X-Request-ID",
                "X-Correlation-ID",
                "X-Session-Token",
                "X-Trace-ID",
                "X-Flow-ID",
                "X-Client-Signature",
                "X-Frontend-ID",
                "X-Telemetry-ID",
            ]
            prefix = secrets.choice(noise_prefixes)
            headers[f"{prefix}-{secrets.randbelow(999) + 1}"] = str(uuid.uuid4())

        # 4. Shuffle Order using Fisher-Yates via secrets
        items = list(headers.items())
        # Fix S4-3: Use exhaustive range for Fisher-Yates shuffle
        for i in range(len(items) - 1, -1, -1):
            j = secrets.randbelow(i + 1)
            items[i], items[j] = items[j], items[i]

        return dict(items)

    def get_stealth_options(self) -> dict[str, Any]:
        """Return advanced stealth parameters for httpx/requests.
        Dynamically adapts based on active False Positive mesh patterns.
        Enhanced with HMM-driven timing and JA3 fingerprinting.
        """
        timeout_choices = [10.0, 12.0, 14.0, 15.0, 16.0, 18.0, 20.0]
        timeout = secrets.choice(timeout_choices)
        http2_chance = 8

        try:
            from src.learning.integration import LearningIntegration

            learning = LearningIntegration.get_or_create()
            if learning and learning.config.enabled:
                import asyncio

                try:
                    loop = asyncio.get_running_loop()
                    active_patterns = loop.run_until_complete(learning.get_active_fp_patterns())
                except RuntimeError:
                    active_patterns = [
                        p.to_db_row() for p in learning._fp_tracker._cache.values() if p.is_active
                    ]

                has_waf_block = any(p.get("category") == "waf_block" for p in active_patterns)
                has_rate_limit = any(p.get("category") == "rate_limit" for p in active_patterns)

                if has_waf_block or has_rate_limit:
                    timeout *= 2.0
                    timeout = min(timeout, 40.0)
                    http2_chance = 10
        except Exception as e:
            logger.debug("Chameleon stealth options adaptation skipped: %s", e)

        evasion_config = self._evasion_engine.get_evasion_config()

        return {
            "follow_redirects": True,
            "timeout": timeout,
            "verify": True,
            "ja3_signature": evasion_config.get(
                "ja3_signature", secrets.choice(self._ja3_signatures)
            ),
            "http2": secrets.randbelow(10) < http2_chance,
            "evasion_state": evasion_config.get("state", "unknown"),
            "timing_delay": evasion_config.get("timing_delay", 0.1),
        }

    def active_checks_requiring_network(self) -> list[dict[str, Any]]:
        """Expose active-check capability queries to frontier scheduling."""
        return [
            manifest.as_dict()
            for manifest in query_active_manifests(capability=ActiveCapability.NETWORK_EGRESS)
        ]


# Singleton instance for pool warming and efficiency
_chameleon = RequestChameleon()


def wrap_polymorphic_request(headers: dict[str, str]) -> dict[str, Any]:
    """Helper to prepare a stealthy polymorphic request.

    Fix #383: Pass a copy of headers to avoid mutating the caller's dict.
    """
    return {
        "headers": _chameleon.mutate_headers(dict(headers)),
        **_chameleon.get_stealth_options(),
    }

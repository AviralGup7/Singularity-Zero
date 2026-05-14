"""
Cyber Security Test Pipeline - Polymorphic Request Engine
Implements real-time fingerprint mutation for WAF and behavioral evasion.
"""

from __future__ import annotations

import secrets
import time
import uuid
from typing import Any

from src.core.logging.trace_logging import get_pipeline_logger

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

    def __init__(self) -> None:
        # Instance copy so subclasses can override without touching class variable
        self._user_agents = list(self._USER_AGENTS)

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
        if secrets.randbelow(10) > 6:  # ~30% chance
            headers[f"X-Frontend-ID-{secrets.randbelow(999) + 1}"] = str(uuid.uuid4())

        # 4. Shuffle Order using Fisher-Yates via secrets
        items = list(headers.items())
        for i in range(len(items) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            items[i], items[j] = items[j], items[i]

        return dict(items)

    def get_stealth_options(self) -> dict[str, Any]:
        """Return advanced stealth parameters for httpx/requests."""
        # Jittered timeout: pick randomly from a range using secrets
        timeout_choices = [10.0, 12.0, 14.0, 15.0, 16.0, 18.0, 20.0]
        return {
            "follow_redirects": True,
            "timeout": secrets.choice(timeout_choices),
            "verify": True,  # GEMINI.md mandate: Default to True for security
        }


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

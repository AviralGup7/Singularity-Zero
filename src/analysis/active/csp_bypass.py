"""Content-Security-Policy bypass probes."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class CspBypassProbe:
    """Utility class that extracts CSP from an HTTP response and runs
    common bypass heuristics against the parsed policy.
    """

    @staticmethod
    def extract_csp(response: Any) -> dict:
        """Parse the CSP header/value from *response* and return a dict bucket by directive."""
        policy_raw = ""
        if hasattr(response, "headers"):
            headers = {str(k).lower(): str(v) for k, v in dict(response.headers or {}).items()}
            policy_raw = headers.get("content-security-policy", "")
        elif isinstance(response, dict):
            hdrs = {str(k).lower(): str(v) for k, v in response.get("headers", {}).items()}
            policy_raw = hdrs.get("content-security-policy", "")
        else:
            policy_raw = str(response or "")

        buckets: dict[str, list[str]] = {}
        for directive_str in policy_raw.split(";"):
            directive_str = directive_str.strip()
            if not directive_str:
                continue
            parts = directive_str.split(None, 1)
            if not parts:
                continue
            directive_name = parts[0]
            values_str = parts[1] if len(parts) > 1 else ""
            buckets.setdefault(directive_name, [])
            if values_str:
                buckets[directive_name].extend(values_str.split())

        return buckets

    def test_unsafe_inline(self, policy: dict) -> dict:
        """Report whether *policy* permits 'unsafe-inline' for script-src."""
        script = policy.get("script-src", [])
        report = {
            "unsafe_inline": False,
            "evidence": script,
        }
        for directive in script:
            for token in directive.split():
                if token in ("'unsafe-inline'", "'unsafe-eval'", "*"):
                    report["unsafe_inline"] = True
        return report

    def test_nonce_bruteforce(self, policy: dict, max_attempts: int = 1000) -> dict:
        """Flag that robust nonces need at least 128 bits of entropy (standard heuristic)."""
        script = " ".join(policy.get("script-src", []))
        nonce_matches = re.findall(r"'nonce-([A-Za-z0-9+/=]+)'", script)
        if not nonce_matches:
            return {
                "nonce_bruteforce_possible": False,
                "reason": "no_nonce_found",
                "max_attempts": 0,
            }
        weakest = min((len(m) for m in nonce_matches), default=0)
        return {
            "nonce_bruteforce_possible": weakest < 16,
            "weakest_nonce_len": weakest,
            "max_attempts": max_attempts if weakest < 16 else 0,
        }

    def test_base_uri_manipulation(self, policy: dict) -> dict:
        """Report whether an overly permissive base-uri enables script-base injection."""
        base = policy.get("base-uri", [])
        if not base:
            return {
                "base_uri_allows_any": False,
                "evidence": base,
            }
        return {
            "base_uri_allows_any": any(
                "'" not in token and token.strip() != "'none'" for token in base
            ),
            "evidence": base,
        }

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
        current: str | None = None
        for token in policy_raw.replace(";", "\n").splitlines():
            token = token.strip()
            if not token:
                continue
            if token.endswith(":"):
                current = token.rstrip(":").strip()
                buckets.setdefault(current, [])
            elif current is not None:
                buckets[current].append(token.strip())

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
            return {"nonce_bruteforce_possible": True, "reason": "no_nonce_found", "max_attempts": max_attempts}
        weakest = min((len(m) for m in nonce_matches), default=0)
        return {
            "nonce_bruteforce_possible": weakest < 16,
            "weakest_nonce_len": weakest,
            "max_attempts": max_attempts if weakest < 16 else 0,
        }

    def test_base_uri_manipulation(self, policy: dict) -> dict:
        """Report whether an overly permissive base-uri enables script-base injection."""
        base = policy.get("base-uri", [])
        return {
            "base_uri_allows_any": any("'" not in token and token.strip() != "'none'" for token in base)
            or not base,
            "evidence": base,
        }

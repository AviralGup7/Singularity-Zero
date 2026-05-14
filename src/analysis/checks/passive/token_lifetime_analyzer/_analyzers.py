"""Token analysis functions for JWT, cookies, and external links."""

import logging
import re
import time
from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature

from ._constants import ONE_HOUR_SECONDS, THIRTY_DAYS_SECONDS, TWENTY_FOUR_HOURS_SECONDS
from ._helpers import compute_confidence, decode_jwt_segment, determine_severity, severity_score

logger = logging.getLogger(__name__)


def analyze_jwt_token(token: str, url: str) -> dict[str, Any] | None:
    """Analyze a JWT token for lifetime and algorithm issues."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    header = decode_jwt_segment(parts[0])
    if not header:
        return None

    payload = decode_jwt_segment(parts[1])
    if not payload:
        return None

    current_time = time.time()
    signals: list[str] = []
    issues: list[str] = []

    alg = str(header.get("alg", "")).strip()
    if alg.lower() == "none":
        signals.append("alg_none")
        issues.append("jwt_alg_none")
    elif alg.startswith("HS"):
        signals.append(f"symmetric_alg:{alg}")
        issues.append("jwt_weak_algorithm")
    elif alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
        signals.append(f"asymmetric_alg:{alg}")

    exp = payload.get("exp")
    if exp is None:
        signals.append("missing_exp_claim")
        issues.append("jwt_no_expiration")
    elif isinstance(exp, (int, float)):
        lifetime = exp - current_time
        if lifetime < 0:
            signals.append("expired_token")
        elif lifetime > THIRTY_DAYS_SECONDS:
            signals.append(f"long_expiration:{lifetime:.0f}s")
            issues.append("jwt_long_expiration")
        elif lifetime > TWENTY_FOUR_HOURS_SECONDS:
            signals.append(f"extended_expiration:{lifetime:.0f}s")
            issues.append("jwt_long_expiration")
        elif lifetime > ONE_HOUR_SECONDS:
            signals.append(f"moderate_expiration:{lifetime:.0f}s")

    iat = payload.get("iat")
    if iat is None:
        signals.append("missing_iat_claim")
        issues.append("jwt_missing_iat")

    nbf = payload.get("nbf")
    if nbf is None:
        signals.append("missing_nbf_claim")
        issues.append("jwt_missing_nbf")

    if not issues:
        return None

    severity = determine_severity(issues)

    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "token_type": "jwt",
        "algorithm": alg,
        "has_expiration": exp is not None,
        "expiration_lifetime": int(exp - current_time) if isinstance(exp, (int, float)) else None,
        "has_issued_at": iat is not None,
        "has_not_before": nbf is not None,
        "claims": list(payload.keys())[:20],
        "signals": sorted(signals),
        "issues": sorted(set(issues)),
        "severity": severity,
        "confidence": compute_confidence(issues),
        "score": severity_score(severity),
    }


def parse_set_cookie(cookie_string: str) -> dict[str, Any]:
    """Parse a Set-Cookie header value into components."""
    result: dict[str, Any] = {
        "name": "",
        "value": "",
        "max_age": None,
        "expires": None,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "raw": cookie_string[:500],
    }

    parts = cookie_string.split(";")
    if not parts:
        return result

    name_value = parts[0].strip()
    if "=" in name_value:
        name, value = name_value.split("=", 1)
        result["name"] = name.strip()
        result["value"] = value.strip()[:200]

    for part in parts[1:]:
        part_stripped = part.strip()
        lowered = part_stripped.lower()

        if lowered == "secure":
            result["secure"] = True
        elif lowered == "httponly":
            result["httponly"] = True
        elif lowered.startswith("samesite="):
            result["samesite"] = part_stripped.split("=", 1)[1].strip().lower()
        elif lowered.startswith("max-age="):
            try:
                result["max_age"] = int(part_stripped.split("=", 1)[1].strip())
            except (ValueError, IndexError) as exc:
                logger.debug("Ignored: %s", exc)
        elif lowered.startswith("expires="):
            result["expires"] = part_stripped.split("=", 1)[1].strip()

    return result


def find_external_links(body: str) -> list[str]:
    """Extract external domain links from response body."""
    external_hosts: set[str] = set()
    url_pattern = re.compile(r"https?://([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,}))")
    for match in url_pattern.finditer(body[:10000]):
        host = match.group(1).lower()
        if host and not any(
            host.endswith(suffix)
            for suffix in (".localhost", ".local", ".internal", ".example.com")
        ):
            external_hosts.add(host)
    return sorted(external_hosts)[:20]

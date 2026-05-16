"""Main JWT security check: auto-discovers tokens and runs the full attack suite."""

import logging
import re
from typing import Any, cast
from urllib.parse import parse_qsl, urlparse

import requests

from src.analysis.helpers import (
    build_endpoint_meta,
    classify_endpoint,
    endpoint_signature,
    normalize_headers,
)
from src.analysis.helpers.scoring import normalized_confidence
from src.core.utils.url_validation import is_safe_url

from .attacks import (
    JWT_AUTH_HEADERS,
    AlgorithmConfusionAttack,
    KidPathTraversalAttack,
    NoneAlgorithmAttack,
    decode_jwt_part,
)
from .expiry import LifetimeManipulationAttack
from .token_manipulation import JkuInjectionAttack, WeakSecretAttack
from .validator import SEVERITY_ORDER, collect_findings, determine_severity

logger = logging.getLogger(__name__)

CHECK_SPEC = {
    "key": "jwt_security_analyzer",
    "label": "JWT Security Analyzer",
    "description": "Analyze JWT tokens for weak algorithms, missing claims, expiration issues, and algorithm confusion vulnerabilities.",
    "group": "session",
    "input_kind": "priority_urls_and_cache",
}

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

JWT_PARAM_NAMES = {
    "token",
    "access_token",
    "jwt",
    "auth_token",
    "bearer",
    "api_token",
    "id_token",
    "refresh_token",
}


def _safe_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    req_headers = dict(headers or {})
    req_headers.setdefault(
        "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityPipeline/1.0"
    )
    req_headers.setdefault("Accept", "application/json, text/html, */*")
    if not is_safe_url(url):
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": "URL failed safety check",
        }
    try:
        resp = requests.request(
            method, url, headers=req_headers, data=body, timeout=timeout, verify=True
        )
        resp_body = resp.text or ""
        return {
            "status": getattr(resp, "status_code", 0),
            "headers": dict(resp.headers),
            "body": resp_body[:8000],
            "body_length": len(resp_body),
            "success": resp.status_code < 400,
        }
    except requests.RequestException as e:
        resp_body = ""
        resp_obj = getattr(e, "response", None)
        status = 0
        headers = {}
        if resp_obj is not None:
            try:
                resp_body = resp_obj.text
                status = getattr(resp_obj, "status_code", 0)
                headers = dict(resp_obj.headers)
            except Exception:  # noqa: S110
                pass
        return {
            "status": status,
            "headers": headers,
            "body": (resp_body or "")[:8000],
            "body_length": len(resp_body or ""),
            "success": False,
            "error": str(e),
        }
    except Exception as e:
        return {
            "status": 0,
            "headers": {},
            "body": "",
            "body_length": 0,
            "success": False,
            "error": str(e),
        }


class _SessionAdapter:
    """Adapter that wraps _safe_request in a requests.Session-like interface."""

    def __init__(self, original_headers: dict[str, str] | None = None):
        self.headers = dict(original_headers or {})

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: int = 10,
        verify: bool = True,
    ) -> Any:
        all_headers = dict(self.headers)
        if headers:
            all_headers.update(headers)
        resp = _safe_request(url, method=method, headers=all_headers, timeout=timeout)
        obj = type("_Response", (), {})()
        setattr(obj, "status_code", resp.get("status", 0))
        setattr(obj, "text", resp.get("body", ""))
        setattr(obj, "headers", resp.get("headers", {}))
        return obj

    def get(self, url: str, timeout: int = 10, verify: bool = True) -> Any:
        return self.request("GET", url, timeout=timeout, verify=verify)

def _extract_jwts_from_response(response: dict[str, Any]) -> list[str]:
    """Extract JWT tokens from response body and headers."""
    tokens: list[str] = []
    body = str(response.get("body_text") or response.get("body") or "")
    for match in JWT_RE.finditer(body):
        token = match.group(0)
        if token not in tokens:
            tokens.append(token)
    headers = response.get("headers", {})
    for key, val in headers.items():
        if isinstance(val, str) and "eyJ" in val:
            for match in JWT_RE.finditer(val):
                token = match.group(0)
                if token not in tokens:
                    tokens.append(token)
    return tokens


def _extract_jwt_from_headers(headers: dict[str, Any]) -> str | None:
    """Extract a JWT token from HTTP auth headers."""
    for header_name in JWT_AUTH_HEADERS:
        val = headers.get(header_name) or headers.get(header_name.lower())
        if val and isinstance(val, str):
            if val.startswith("Bearer "):
                val = val[7:]
            if JWT_RE.match(val):
                return cast(str, val)
    return None


def _build_finding(
    url: str,
    category: str,
    title: str,
    severity: str,
    confidence: float,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
) -> dict[str, Any]:
    """Build a standardized vulnerability finding dict."""
    meta = build_endpoint_meta(url)
    score_map = {"critical": 100, "high": 80, "medium": 50, "low": 20, "info": 5}
    return {
        "url": url,
        "endpoint_key": meta["endpoint_key"],
        "endpoint_base_key": meta["endpoint_base_key"],
        "endpoint_type": meta["endpoint_type"],
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": round(confidence, 2),
        "score": score_map.get(severity, 20),
        "signals": sorted(set(signals)),
        "evidence": evidence,
        "explanation": explanation,
    }


def run_jwt_attack_suite(token: str, url: str, session: Any, config: Any = None) -> dict[str, Any]:
    """Run the full JWT attack suite against a target URL.

    Args:
        token: The JWT token to test with.
        url: The target URL to test against.
        session: HTTP session object (requests.Session or similar).
        config: Optional configuration dict.

    Returns:
        dict with attack results, summary, and findings.
    """
    logger.info("Starting JWT attack suite on %s", url)

    alg_none = NoneAlgorithmAttack(token)
    alg_confusion = AlgorithmConfusionAttack(token)
    kid_traversal = KidPathTraversalAttack(token)
    weak_secret = WeakSecretAttack(token)
    lifetime = LifetimeManipulationAttack(token)
    jku = JkuInjectionAttack(token)

    attacks: dict[str, dict[str, Any]] = {
        "alg_none": alg_none.execute(url, session),
        "algorithm_confusion": alg_confusion.execute(url, session),
        "kid_traversal": kid_traversal.execute(url, session),
        "weak_secret": weak_secret.execute(url, session),
        "lifetime_manipulation": lifetime.execute(url, session),
        "jku_injection": jku.execute(url, session),
    }

    vulnerable_attacks = [name for name, result in attacks.items() if result.get("vulnerable")]
    total_tests = len(attacks)
    vulnerable_count = len(vulnerable_attacks)
    severity = determine_severity(vulnerable_count)
    findings = collect_findings(attacks)

    return {
        "url": url,
        "token_preview": token[:30] + "..." if len(token) > 30 else token,
        "total_attacks": total_tests,
        "vulnerable_attacks": vulnerable_count,
        "vulnerable_list": vulnerable_attacks,
        "severity": severity,
        "attacks": attacks,
        "findings": findings,
    }


def jwt_security_analyzer(
    priority_urls: list[dict[str, Any]] | None = None,
    response_cache: Any = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Analyze JWT tokens for security vulnerabilities.

    Discovers JWT tokens in responses and headers, then runs the full
    JWT attack suite including alg=none, algorithm confusion, kid traversal,
    weak secrets, lifetime manipulation, and jku injection.

    Args:
        priority_urls: List of URL dicts with endpoint information.
        response_cache: Response cache for retrieving original responses.
        limit: Maximum number of findings to return.

    Returns:
        List of JWT vulnerability findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    if not priority_urls:
        return findings

    for item in priority_urls:
        if len(findings) >= limit:
            break

        url = str(item.get("url", "")).strip()
        if not url or not url.startswith(("http://", "https://")):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        resp = None
        if response_cache is not None:
            try:
                resp = response_cache.get(url)
            except Exception:  # noqa: S110
                logger.warning("Cache lookup failed for %s", url)
                pass

        if not resp:
            resp = _safe_request(url, timeout=8)
        if not resp or resp.get("status") in (404, 410, 503):
            continue

        jwt_token = _extract_jwt_from_headers(resp.get("headers", {}))
        if not jwt_token:
            jwts = _extract_jwts_from_response(resp)
            if jwts:
                jwt_token = jwts[0]

        if not jwt_token:
            parsed = urlparse(url)
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            for k, v in query_pairs:
                if k.lower() in JWT_PARAM_NAMES and JWT_RE.match(v):
                    jwt_token = v
                    break

        if not jwt_token:
            continue

        parts = jwt_token.split(".")
        if len(parts) != 3:
            continue

        header = decode_jwt_part(parts[0])
        payload = decode_jwt_part(parts[1])
        if not header or not payload:
            continue

        original_headers = normalize_headers(resp) if resp else {}
        session = _SessionAdapter(original_headers)

        result = run_jwt_attack_suite(jwt_token, url, session)

        if not result.get("findings"):
            continue

        signals: list[str] = []
        attack_details: list[dict[str, Any]] = []
        highest_severity = "info"

        for finding in result["findings"]:
            finding_type = finding.get("finding", "")
            signals.append(finding_type)
            attack_details.append(finding)

            finding_severity = {
                "alg_none_bypass_auth_bypass": "critical",
                "alg_confusion_rs256_to_hs256_bypass": "critical",
                "kid_traversal_auth_bypass": "high",
                "kid_traversal_file_content_leak": "critical",
                "weak_secret_accepted": "critical",
                "weak_secret_admin_reflection": "high",
                "lifetime_expired_token_bypass": "high",
                "lifetime_expired_token_accepted": "high",
                "lifetime_far_future_expiry": "medium",
                "lifetime_missing_exp": "medium",
                "jku_injection_auth_bypass": "high",
            }.get(finding_type, "medium")
            if SEVERITY_ORDER.get(finding_severity, 4) < SEVERITY_ORDER.get(highest_severity, 4):
                highest_severity = finding_severity

        unique_attacks = list({f["attack"] for f in result["findings"]})
        title = f"JWT vulnerability: {', '.join(unique_attacks)}"

        confidence = normalized_confidence(
            base=0.85 if highest_severity in ("critical", "high") else 0.65,
            score=9 if highest_severity == "critical" else 7 if highest_severity == "high" else 5,
            signals=signals,
        )

        evidence = {
            "token_preview": result.get("token_preview", ""),
            "total_attacks": result.get("total_attacks", 0),
            "vulnerable_attacks": result.get("vulnerable_attacks", 0),
            "vulnerable_list": result.get("vulnerable_list", []),
            "attack_details": attack_details[:10],
            "original_algorithm": header.get("alg", "unknown")
            if isinstance(header, dict)
            else "unknown",
        }

        explanation = (
            f"JWT token on '{url}' is vulnerable to {result['vulnerable_attacks']} attack(s): "
            f"{', '.join(unique_attacks)}. "
            f"Original algorithm: {evidence['original_algorithm']}. "
            f"Tested {result['total_attacks']} attack vectors."
        )

        findings.append(
            _build_finding(
                url=url,
                category="jwt_vulnerability",
                title=title,
                severity=highest_severity,
                confidence=confidence,
                signals=signals,
                evidence=evidence,
                explanation=explanation,
            )
        )

    findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 5),
            -f["confidence"],
            f["url"],
        )
    )

    return findings[:limit]

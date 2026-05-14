"""Live XSS reflection probe.

Detects reflected XSS by injecting test markers into URL parameters,
analyzing HTML context, detecting WAF interference, scoring reflection
efficiency, and generating/confirming context-aware XSS payloads.

Flow (inspired by XSStrike):
  1. Inject a safe marker into each URL parameter (reflection test).
  2. Parse the response to find where the marker lands (context detection).
  3. Detect WAF presence from the response.
  4. Score reflection efficiency (fuzzy match of marker in body).
  5. For contexts that look exploitable, generate targeted payloads.
  6. Inject those payloads and measure execution confidence.

Each finding includes confidence, efficiency score, WAF status, and the
HTML context where the reflection occurred.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.active.injection._context_detector import (
    ContextDetector,
    ReflectionContext,
)
from src.analysis.active.injection._efficiency import (
    reflection_efficiency,
    score_payload_executability,
)
from src.analysis.active.injection._payload_generator import PayloadGenerator
from src.analysis.active.injection._waf_detector import WafDetector
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

logger = logging.getLogger(__name__)

XSS_REFLECT_MARKER = "v3dm0s"

_DANGER_FUNC_REDS = {
    func: re.compile(rf"{func}\s*\([^)]*\)", re.I) for func in ("confirm", "prompt", "alert")
}
_DOMAIN_REDACT_RE = re.compile(r"//[\w.]+")

COMMON_PARAM_NAMES = frozenset(
    [
        "q",
        "query",
        "search",
        "keyword",
        "s",
        "input",
        "text",
        "url",
        "redirect",
        "redir",
        "goto",
        "return_to",
        "next",
        "continue",
        "name",
        "user",
        "username",
        "email",
        "debug",
        "test",
        "callback",
        "jsonp",
        "redirect_uri",
        "return_url",
        "back",
        "title",
        "message",
        "msg",
        "comment",
        "body",
        "id",
        "uid",
        "page",
        "p",
        "lang",
        "locale",
        "data",
        "file",
        "path",
        "location",
        "href",
        "src",
        "token",
        "api_key",
        "key",
        "value",
    ]
)

REFLECT_CONFIDENCE = {
    "highly_executable": 0.95,
    "likely_executable": 0.82,
    "possibly_executable": 0.68,
    "filtered": 0.45,
    "blocked": 0.20,
}

REFLECT_SEVERITY = {
    "highly_executable": "critical",
    "likely_executable": "high",
    "possibly_executable": "medium",
    "filtered": "low",
    "blocked": "info",
}


def xss_reflect_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Probe URLs for reflected XSS using context-aware analysis."""
    findings: list[dict[str, Any]] = []
    waf_detector = WafDetector()

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = _extract_url(url_entry)
        if not url or "?" not in url:
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        params_to_test = _select_params(query_pairs)
        if not params_to_test:
            continue

        baseline = response_cache.get(url)
        (baseline or {}).get("body_text", "")

        for param_idx, param_name in params_to_test:
            if len(findings) >= limit:
                break

            test_url = _build_test_url(url, query_pairs, param_idx, XSS_REFLECT_MARKER)

            response = response_cache.request(
                test_url,
                headers={"Cache-Control": "no-cache", "X-XSS-Probe": "1"},
            )
            if not response:
                logger.debug("No response for %s", test_url)
                continue

            body = response.get("body_text", "")
            status_code = response.get("status_code", 0)
            headers = response.get("headers", {})

            if not body or XSS_REFLECT_MARKER.lower() not in body.lower():
                continue

            logger.info(
                "XSS reflection found: param=%s in %s",
                param_name,
                url,
            )

            # Context detection
            detector = ContextDetector(body, marker=XSS_REFLECT_MARKER)
            contexts = detector.detect_all()

            # Reflection efficiency scoring
            efficiency = reflection_efficiency(body, XSS_REFLECT_MARKER)

            # WAF detection
            waf_result = waf_detector.detect_from_response(
                url=test_url,
                status_code=status_code,
                response_body=body,
                response_headers=headers,
                triggered_by_injection=True,
            )

            base_finding = _build_finding(
                url=url,
                param_name=param_name,
                contexts=contexts,
                efficiency=efficiency,
                waf_result=waf_result,
                response=response,
                test_marker=XSS_REFLECT_MARKER,
            )

            # Payload testing if efficiency is high enough
            if efficiency >= 60 and contexts:
                payload_findings = _test_payloads(
                    url=url,
                    query_pairs=query_pairs,
                    param_idx=param_idx,
                    contexts=contexts,
                    base_finding=base_finding,
                    waf_active=waf_result.detected,
                    response_cache=response_cache,
                    url_entry=url_entry,
                )
                findings.extend(payload_findings)
            else:
                findings.append(base_finding)

            if waf_result.detected:
                time.sleep(2)

    findings.sort(key=lambda f: f.get("confidence", 0), reverse=True)
    return findings[:limit]


def _test_payloads(
    url: str,
    query_pairs: list[tuple[str, str]],
    param_idx: int,
    contexts: list[ReflectionContext],
    base_finding: dict[str, Any],
    waf_active: bool,
    response_cache: ResponseCache,
    url_entry: dict[str, Any],
) -> list[dict[str, Any]]:
    """Test generated payloads against the target URL."""
    gen = PayloadGenerator(contexts, include_evasion=not waf_active)
    payload_vectors = gen.generate()

    if not payload_vectors:
        return [base_finding]

    findings: list[dict[str, Any]] = []
    max_payloads = 30 if waf_active else 60
    tested = 0

    for confidence_level in sorted(payload_vectors.keys(), reverse=True):
        payloads = list(payload_vectors[confidence_level])
        if waf_active and confidence_level < 5:
            continue

        for entry in payloads:
            if tested >= max_payloads:
                break

            test_url = _build_test_url(url, query_pairs, param_idx, entry.vector)

            response = response_cache.request(
                test_url,
                headers={"Cache-Control": "no-cache", "X-XSS-Probe": "1"},
            )
            if not response:
                tested += 1
                continue

            body = response.get("body_text", "")
            best_context = _select_context(body, contexts)
            ctx_type = best_context.context if best_context else "html"

            score, verdict = score_payload_executability(body, entry.vector, ctx_type)

            if score >= 70:
                findings.append(
                    {
                        **base_finding,
                        "confirmed": True,
                        "payload": _redact_payload(entry.vector),
                        "confidence": REFLECT_CONFIDENCE.get(verdict, 0.5),
                        "severity": REFLECT_SEVERITY.get(verdict, "low"),
                        "efficiency": score,
                        "verdict": verdict,
                        "context": ctx_type,
                        "context_detail": entry.description,
                        "category": "reflected_xss_confirmed",
                        "title": (f"Reflected XSS confirmed in parameter via {entry.description}"),
                        "response_status": response.get("status_code"),
                    }
                )
                logger.info(
                    "XSS PAYLOAD CONFIRMED: %s -> %s (score=%d)",
                    url,
                    verdict,
                    score,
                )
            elif score >= 40:
                findings.append(
                    {
                        **base_finding,
                        "confirmed": False,
                        "payload": _redact_payload(entry.vector),
                        "confidence": score / 100.0,
                        "severity": "medium" if score >= 50 else "low",
                        "efficiency": score,
                        "verdict": verdict,
                        "context": ctx_type,
                        "context_detail": entry.description,
                        "category": "reflected_xss_possible",
                        "title": f"Possible reflected XSS via {entry.description}",
                    }
                )

            tested += 1

            if waf_active:
                time.sleep(1)

    return findings if findings else [base_finding]


def _build_finding(
    url: str,
    param_name: str,
    contexts: list[ReflectionContext],
    efficiency: int,
    waf_result: Any,
    response: dict[str, Any],
    test_marker: str,
) -> dict[str, Any]:
    """Build a structured XSS reflection finding."""
    context_types = [c.context for c in contexts]
    has_dead = "dead" in context_types
    has_script = "script" in context_types

    base_confidence = efficiency / 100.0

    if has_script:
        base_confidence = min(0.95, base_confidence * 1.2)
        severity = "high"
    elif has_dead:
        base_confidence *= 0.3
        severity = "low"
    elif efficiency >= 80:
        severity = "high"
    elif efficiency >= 60:
        severity = "medium"
    else:
        severity = "low"

    if waf_result.detected:
        base_confidence *= 0.6
        severity = "medium" if severity in ("critical", "high") else severity

    return {
        "url": url,
        "parameter": param_name,
        "reflection_count": len(contexts),
        "contexts": context_types,
        "efficiency": efficiency,
        "confidence": round(base_confidence, 2),
        "severity": severity,
        "category": "reflected_xss_reflection",
        "title": (
            f"XSS reflection detected in parameter '{param_name}' ({efficiency}% efficiency)"
        ),
        "waf_detected": waf_result.detected,
        "waf_name": waf_result.waf_name,
        "confirmed": False,
        "payload": None,
        "marker": test_marker,
        "response_status": response.get("status_code"),
    }


def _extract_url(url_entry: Any) -> str | None:
    """Extract URL string from a URL dict entry."""
    if isinstance(url_entry, dict):
        return str(url_entry.get("url", "")).strip() or None
    return str(url_entry).strip() or None


def _build_test_url(
    url: str,
    query_pairs: list[tuple[str, str]],
    param_idx: int,
    value: str,
) -> str:
    """Build a test URL with one parameter replaced by the test value."""
    updated = list(query_pairs)
    updated[param_idx] = (updated[param_idx][0], value)
    parsed = urlparse(url)
    return normalize_url(urlunparse(parsed._replace(query=urlencode(updated, doseq=True))))


def _select_params(
    query_pairs: list[tuple[str, str]],
) -> list[tuple[int, str]]:
    """Select parameters worth testing for XSS reflection."""
    selected: list[tuple[int, str]] = []
    for i, (name, value) in enumerate(query_pairs):
        if name.lower() in COMMON_PARAM_NAMES:
            selected.append((i, name))

    if not selected:
        for i, (name, value) in enumerate(query_pairs[:3]):
            selected.append((i, name))

    return selected


def _select_context(
    body: str,
    contexts: list[ReflectionContext],
) -> ReflectionContext | None:
    """Select the most exploitable context based on response body."""
    live = [c for c in contexts if c.context != "dead"]
    if not live:
        return None

    priority = {"script": 0, "html": 1, "attribute": 2, "comment": 3}
    return sorted(live, key=lambda c: priority.get(c.context, 99))[0]


def _redact_payload(payload: str) -> str:
    """Redact the potentially dangerous parts of a payload for safe reporting."""
    redacted = payload
    for func in ("confirm", "prompt", "alert"):
        redacted = _DANGER_FUNC_REDS[func].sub(f"{func}(REDACTED)", redacted)
    redacted = _DOMAIN_REDACT_RE.sub("//[redacted-domain]", redacted)
    return redacted


__all__ = ["xss_reflect_probe"]

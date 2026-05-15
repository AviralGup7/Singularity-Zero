"""SSTI (Server-Side Template Injection) detector for identifying template injection surfaces.

Analyzes responses for template engine error patterns, reflection contexts,
and parameter surfaces that are vulnerable to SSTI attacks across multiple
template engines (Jinja2, Twig, Freemarker, Velocity, ERB, etc.).
"""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    endpoint_signature,
    is_noise_url,
    meaningful_query_pairs,
    normalized_confidence,
)
from src.analysis.passive.extended_shared import build_response_index, compute_severity, record
from src.recon.common import normalize_url

# SSTI payload patterns for different template engines
# These are safe test payloads that are unlikely to cause damage
SSTI_TEST_PAYLOADS = [
    ("${7*7}", "freemarker"),  # Freemarker/Java EL
    ("#{7*7}", "spring_el"),  # Spring Expression Language
    ("{{7*7}}", "jinja2_twig"),  # Jinja2/Twig/Nunjucks
    ("<%= 7*7 %>", "erb"),  # ERB (Ruby)
    ("#{7*7}", "velocity"),  # Velocity (Java)
    ("${{7*7}}", "mustache"),  # Mustache/Handlebars
    ("@(7*7)", "razor"),  # Razor (ASP.NET)
]

# SSTI error patterns in responses
SSTI_ERROR_PATTERNS = [
    # Jinja2/Twig errors
    r"undefinederror",
    r"template syntax error",
    r"jinja2",
    r"twig_error",
    r"unexpected char",
    r"unexpected token",
    r"syntax error.*template",
    # Freemarker errors
    r"freemarker",
    r"template exception",
    r"expression.*undefined",
    # ERB errors
    r"actionview",
    r"erb.*error",
    r"syntax error.*erb",
    # Generic template errors
    r"template.*error",
    r"template.*exception",
    r"rendering.*error",
    r"parse error.*template",
    r"compilation error.*template",
]

# Template engine detection patterns in responses
TEMPLATE_ENGINE_PATTERNS = [
    (r"jinja2|flask.*template", "jinja2"),
    (r"twig.*template|symfony.*template", "twig"),
    (r"freemarker|ftl.*template", "freemarker"),
    (r"velocity.*template|vtl", "velocity"),
    (r"erb.*template|rails.*template|actionview", "erb"),
    (r"mustache|handlebars|hbs", "mustache"),
    (r"razor|asp.*net.*template|cshtml", "razor"),
    (r"spring.*template|thymeleaf", "spring"),
]

SSTI_ERROR_RE = re.compile("|".join(SSTI_ERROR_PATTERNS), re.IGNORECASE)


def _detect_template_engine(body: str) -> list[str]:
    """Detect template engine fingerprints in response body.

    Args:
        body: Response body text.

    Returns:
        List of detected template engine names.
    """
    engines = []
    for pattern, engine in TEMPLATE_ENGINE_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            engines.append(engine)
    return engines


def _check_ssti_reflection(body: str, payload: str) -> list[str]:
    """Check if SSTI payload was processed (computed) vs just reflected.

    Args:
        body: Response body text.
        payload: The SSTI test payload that was sent.

    Returns:
        List of SSTI reflection signals.
    """
    signals = []
    body_lower = body.lower()
    payload_lower = payload.lower()

    # Check if payload was computed (49 = 7*7) - require context near template syntax
    if "49" in body_lower and payload_lower not in body_lower:
        has_template_context = any(
            kw in body_lower
            for kw in ("{{", "}}", "{%", "%}", "${", "#{", "<%=", "template", "render")
        )
        if has_template_context:
            signals.append("ssti_computed_result")
    # Check if payload was reflected as-is
    elif payload_lower in body_lower:
        signals.append("ssti_reflected_raw")
    # Check if payload caused an error
    if SSTI_ERROR_RE.search(body):
        signals.append("ssti_error_response")

    return signals


def _build_ssti_explanation(
    engines: list[str],
    template_params: set[str],
    has_error: bool,
    template_values: set[str] | None = None,
) -> str:
    """Build human-readable explanation for SSTI finding."""
    parts = []
    if engines:
        parts.append(f"Template engine(s) detected: {', '.join(engines)}")
    if template_params:
        parts.append(f"Template-relevant parameters: {', '.join(sorted(template_params))}")
    if template_values:
        parts.append(
            f"Parameter values contain template syntax: {', '.join(sorted(template_values))}"
        )
    if has_error:
        parts.append("SSTI error pattern detected in response")
    return "; ".join(parts) if parts else "SSTI surface detected"


def ssti_surface_detector(urls: set[str], responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect potential SSTI surfaces by analyzing responses for template engine patterns.

    This is a passive detector that identifies:
    - Template engine fingerprints in responses
    - Parameters that look like template variables
    - Error responses that suggest template processing

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.

    Returns:
        List of SSTI surface findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    response_by_url = build_response_index(responses)

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        response = response_by_url.get(normalize_url(url))
        if not response:
            continue

        body = str(response.get("body_text") or "")[:8000]
        if not body:
            continue

        # Detect template engine fingerprints
        engines = _detect_template_engine(body)

        # Check for template-like parameter names (expanded coverage)
        query_pairs = meaningful_query_pairs(url)
        template_param_names = {
            "template",
            "tpl",
            "view",
            "layout",
            "render",
            "page",
            "theme",
            "skin",
            "name",
            "title",
            "message",
            "content",
            "body",
            "subject",
            "description",
            "text",
            "comment",
            "note",
            "label",
            "header",
            "footer",
        }
        template_params = {name for name, _ in query_pairs if name.lower() in template_param_names}

        # Check for template-like parameter VALUES (e.g., ?name={{user.name}})
        template_value_patterns = {
            "jinja2_twig": re.compile(r"\{\{.*\}\}|\{%.*%\}", re.IGNORECASE),
            "freemarker": re.compile(r"\$\{.*\}|<#.*>", re.IGNORECASE),
            "erb": re.compile(r"<%=.*%>|<%#.*%>", re.IGNORECASE),
            "razor": re.compile(r"@\w+\(|@Render", re.IGNORECASE),
            "mustache": re.compile(r"\{\{#.*\}\}|\{\{\\?.*\}\}", re.IGNORECASE),
        }
        template_values_found = set()
        for name, value in query_pairs:
            for engine_name, pattern in template_value_patterns.items():
                if pattern.search(value):
                    template_values_found.add(engine_name)

        # Check for SSTI error patterns in response
        has_ssti_error = bool(SSTI_ERROR_RE.search(body))

        # Collect signals
        signals: list[str] = []
        if engines:
            signals.extend(f"engine:{e}" for e in engines)
        if template_params:
            signals.extend(f"param:{p}" for p in sorted(template_params))
        if template_values_found:
            signals.extend(f"template_value:{e}" for e in sorted(template_values_found))
        if has_ssti_error:
            signals.append("ssti_error_pattern")

        # Only report if we have meaningful signals
        if not signals:
            continue

        seen.add(endpoint_key)

        # Calculate risk score with engine-specific bonuses
        risk_score = 0
        if engines:
            risk_score += 3 * len(engines)
            # Engine-specific confidence bonuses
            # Jinja2/Twig are most commonly vulnerable
            if "jinja2" in engines or "twig" in engines:
                risk_score += 2
            # Freemarker/Velocity are enterprise targets
            if "freemarker" in engines or "velocity" in engines:
                risk_score += 2
            # ERB/Razor indicate specific frameworks
            if "erb" in engines or "razor" in engines:
                risk_score += 1
        if template_params:
            risk_score += 2 * len(template_params)
        if template_values_found:
            risk_score += 4 * len(template_values_found)  # High risk if values look like templates
        if has_ssti_error:
            risk_score += 5

        # Engine correlation bonus: multiple engines detected = higher confidence
        engine_correlation_bonus = 0.0
        if len(engines) >= 2:
            engine_correlation_bonus = 0.08 * (len(engines) - 1)
        if template_values_found:
            engine_correlation_bonus += 0.10 * len(template_values_found)

        findings.append(
            record(
                url,
                status_code=response.get("status_code"),
                ssti_signals=signals,
                detected_engines=engines,
                template_parameters=sorted(template_params),
                template_values_found=sorted(template_values_found),
                has_ssti_error=has_ssti_error,
                risk_score=risk_score,
                severity=compute_severity(risk_score),
                confidence=round(
                    min(
                        normalized_confidence(
                            base=0.45, score=risk_score, signals=signals, cap=0.92
                        )
                        + engine_correlation_bonus,
                        0.98,
                    ),
                    2,
                ),
                explanation=_build_ssti_explanation(
                    engines, template_params, has_ssti_error, template_values_found
                ),
                content_type=response.get("content_type", ""),
            )
        )

    findings.sort(key=lambda item: (-item.get("risk_score", 0), item.get("url", "")))
    return findings


def ssti_active_probe(
    priority_urls: list[dict[str, Any]], response_cache: Any, limit: int = 10
) -> list[dict[str, Any]]:
    """Send safe SSTI test payloads to template-relevant parameters and check for computed results.

    This probe sends harmless mathematical expressions in template syntax to parameters
    that look like template variables and checks if the result is computed (49) or
    if template errors are triggered.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of SSTI probe findings with detected computation or errors.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    template_param_names = {
        "template",
        "tpl",
        "view",
        "layout",
        "render",
        "page",
        "theme",
        "skin",
        "name",
        "title",
        "message",
        "content",
        "text",
        "body",
        "subject",
    }

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url or is_noise_url(url):
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        # Find template-relevant parameters
        template_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in template_param_names
        ]
        if not template_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        url_findings: list[dict[str, Any]] = []

        for idx, param_name, param_value in template_params:
            # Test with Jinja2/Twig payload (most common)
            test_payload = "{{7*7}}"
            updated = list(query_pairs)
            updated[idx] = (param_name, test_payload)
            test_url = normalize_url(
                urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
            )

            response = response_cache.request(
                test_url,
                headers={"Cache-Control": "no-cache", "X-SSTI-Probe": "1"},
            )
            if not response:
                continue

            body = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)
            ssti_signals = _check_ssti_reflection(body, test_payload)

            if ssti_signals:
                url_findings.append(
                    {
                        "parameter": param_name,
                        "payload": test_payload,
                        "payload_type": "jinja2_twig",
                        "status_code": status,
                        "ssti_signals": ssti_signals,
                        "computed_result": "ssti_computed_result" in ssti_signals,
                    }
                )
                break  # Stop after first SSTI signal for this URL

        if url_findings:
            seen.add(endpoint_key)
            has_computation = any(f.get("computed_result") for f in url_findings)
            has_error = any(
                "ssti_error_response" in f.get("ssti_signals", []) for f in url_findings
            )

            findings.append(
                record(
                    url,
                    status_code=url_findings[0].get("status_code"),
                    ssti_probe_signals=[s for f in url_findings for s in f.get("ssti_signals", [])],
                    probes=url_findings,
                    ssti_computed=has_computation,
                    ssti_error=has_error,
                    severity="high" if has_computation else "medium" if has_error else "low",
                    confidence=0.92 if has_computation else 0.75 if has_error else 0.60,
                )
            )

    findings.sort(key=lambda item: (-item.get("confidence", 0), item.get("url", "")))
    return findings

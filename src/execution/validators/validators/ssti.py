"""SSTI (Server-Side Template Injection) validation for endpoints with template engine fingerprints.

Validates SSTI candidates by analyzing passive detection results, performing
active template injection tests, and verifying template engine behavior.
"""

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

# Template engine detection patterns
TEMPLATE_ENGINES = {
    "jinja2": {"{{", "{%", "extends", "block", "include"},
    "twig": ["{{", "{%", "extends", "block", "include"],
    "freemarker": ["${", "<#", "include", "assign"],
    "velocity": ["$!", "$(", "#set", "#include", "#parse"],
    "erb": ["<%=", "<%", "<%#", "<%-"],
    "mustache": ["{{", "{{{", "{{#", "{{/", "{{^"],
    "razor": ["@model", "@Html", "@Url", "@Render"],
    "spring": ["${", "#{", "@{", "*{"],
}

# SSTI payloads organized by template engine
SSTI_PAYLOADS = {
    "jinja2": [
        ("{{7*7}}", "49"),
        ("{{config}}", "config"),
        ("{{self.__dict__}}", "__dict__"),
        ("{{7*'7'}}", "7777777"),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "subclass"),
        ("{{request.application.__globals__}}", "globals"),
    ],
    "twig": [
        ("{{7*'7'}}", "49"),
        ("{{dump(app)}}", "dump"),
        ("{{7*7}}", "49"),
        (
            "{{_self.env.registerUndefinedFilterCallback('exec')}}",
            "registerUndefinedFilterCallback",
        ),
    ],
    "freemarker": [
        ("<#assign x=1>", "assign"),
        ("${7*7}", "49"),
        ("<#list 1..1 as i>${i}</#list>", "1"),
        ("${.now}", "now"),
    ],
    "velocity": [
        ("#set($x=1)", "set"),
        ("${7*7}", "49"),
        ("#set($x=$request.get('foo'))", "request"),
        ("$!{request}", "request"),
    ],
    "erb": [
        ("<%= 7*7 %>", "49"),
        ("<%= system('id') %>", "uid="),
        ("<%= 7*7 %>", "49"),
        ("<%= File.read('/etc/passwd') %>", "root:"),
    ],
    "generic": [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("[[7*7]]", "49"),
    ],
}

# SSTI error patterns to detect in responses
SSTI_ERROR_PATTERNS = [
    r"TemplateSyntaxError",
    r"UndefinedError",
    r"TemplateNotFound",
    r"Jinja2",
    r"Twig_Error",
    r"Freemarker.*Exception",
    r"Velocity.*Exception",
    r"ActionView::Template::Error",
    r"ERB.*Error",
    r"SyntaxError.*template",
    r"unexpected.*token",
    r"unclosed.*tag",
    r"undefined.*variable",
    r"unknown.*filter",
    r"template.*rendering.*error",
]

# Math evaluation indicators (proves code execution)
MATH_EVALUATION_PATTERNS = [
    (r"\b49\b", "7*7 evaluated"),
    (r"\b14\b", "7+'7' or 7+7 evaluated"),
    (r"\b343\b", "7*7*7 evaluated"),
    (r"\b16807\b", "7**5 evaluated"),
    (r"\b823543\b", "7**7 evaluated"),
]


def _detect_math_evaluation(response_body: str, payload: str) -> list[str]:
    """Check if the response contains evidence of mathematical expression evaluation.

    Args:
        response_body: The HTTP response body.
        payload: The SSTI payload that was sent.

    Returns:
        List of detected math evaluation indicators.
    """
    if not response_body:
        return []

    evaluations = []

    for pattern, description in MATH_EVALUATION_PATTERNS:
        match = re.search(pattern, response_body)
        if match:
            payload_not_literal = payload not in response_body
            if payload_not_literal or f"={match.group()}" in response_body.lower():
                evaluations.append(description)

    return evaluations


def _detect_template_errors(response_body: str) -> list[str]:
    """Check response body for template engine error messages.

    Args:
        response_body: The HTTP response body to analyze.

    Returns:
        List of detected template error patterns.
    """
    if not response_body:
        return []

    errors = []
    for pattern in SSTI_ERROR_PATTERNS:
        if re.search(pattern, response_body, re.IGNORECASE):
            errors.append(pattern)

    return errors


def _detect_engine_from_response(response_body: str) -> list[str]:
    """Detect which template engine may be in use based on response content.

    Args:
        response_body: The HTTP response body to analyze.

    Returns:
        List of detected template engine names.
    """
    if not response_body:
        return []

    detected = []
    body_lower = response_body.lower()

    engine_indicators = {
        "jinja2": ["jinja2", "flask template", "werkzeug"],
        "twig": ["twig", "symfony template", "drupal template"],
        "freemarker": ["freemarker", "ftl template"],
        "velocity": ["velocity", "vm template"],
        "erb": ["erb", "rails template", "actionview"],
        "razor": ["razor", "asp.net mvc", "cshtml"],
        "spring": ["spring template", "thymeleaf"],
    }

    for engine, indicators in engine_indicators.items():
        if any(indicator in body_lower for indicator in indicators):
            detected.append(engine)

    return detected


def _active_ssti_test(target_url: str, http_client: Any) -> dict[str, Any]:
    """Perform active SSTI testing against the target URL.

    Args:
        target_url: The URL to test.
        http_client: HTTP client for making requests.

    Returns:
        Dict with active SSTI test results.
    """
    if not http_client:
        return {"status": "skipped", "reason": "no_http_client"}

    parsed = urlparse(target_url)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    test_results: list[dict[str, Any]] = []
    math_evaluations: list[str] = []
    template_errors: list[str] = []
    code_execution_indicators: list[str] = []
    engines_detected: list[str] = []

    if not query_params:
        return {
            "status": "skipped",
            "reason": "no_query_params",
            "url": target_url,
        }

    for param_name in list(query_params.keys())[:3]:
        original_value = query_params[param_name]

        for engine, payloads in SSTI_PAYLOADS.items():
            for payload, expected_indicator in payloads[:3]:
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

                    payload_reflected = payload.lower() in body.lower()
                    math_evals = _detect_math_evaluation(body, payload)
                    errors = _detect_template_errors(body)

                    if math_evals:
                        math_evaluations.extend(math_evals)
                        code_execution_indicators.append(f"math_eval:{payload}")

                    if errors:
                        template_errors.extend(errors)

                    if not payload_reflected and (math_evals or errors):
                        test_results.append(
                            {
                                "param": param_name,
                                "engine": engine,
                                "payload": payload,
                                "reflected": False,
                                "math_evaluation": bool(math_evals),
                                "template_error": bool(errors),
                                "status_code": status_code,
                                "indicator": expected_indicator,
                            }
                        )
                    elif payload_reflected and not any(
                        re.escape(payload) in body or payload in body for _ in [1]
                    ):
                        test_results.append(
                            {
                                "param": param_name,
                                "engine": engine,
                                "payload": payload,
                                "reflected": True,
                                "sanitized": True,
                                "status_code": status_code,
                            }
                        )
                except Exception as exc:
                    test_results.append(
                        {
                            "param": param_name,
                            "engine": engine,
                            "payload": payload,
                            "error": str(exc),
                        }
                    )

        query_params[param_name] = original_value

    if test_results:
        sample_response = http_client.request(target_url)
        body = str(sample_response.get("body", ""))
        engines_detected = _detect_engine_from_response(body)

    unique_math = sorted(set(math_evaluations))
    unique_errors = sorted(set(template_errors))
    unique_engines = sorted(set(engines_detected))

    if unique_math:
        status = "confirmed"
    elif unique_errors:
        status = "potential"
    else:
        status = "not_vulnerable"

    return {
        "status": status,
        "url": target_url,
        "test_results": test_results[:20],
        "math_evaluations": unique_math[:10],
        "template_errors": unique_errors[:10],
        "engines_detected": unique_engines,
        "code_execution_indicators": code_execution_indicators[:10],
        "evaluations_count": len(unique_math),
        "errors_count": len(unique_errors),
        "payloads_tested": len(test_results),
    }


def validate_ssti_candidates(
    analysis_results: dict[str, Any],
    callback_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Validate SSTI protection on endpoints with template engine fingerprints.

    Analyzes results from passive SSTI detectors to identify endpoints
    that may be vulnerable to server-side template injection.

    Args:
        analysis_results: Results from passive analysis modules.
        callback_context: Optional callback context with validation state.

    Returns:
        List of SSTI validation findings.
    """
    findings: list[dict[str, Any]] = []
    seen_patterns: set[str] = set()

    # Get SSTI-related findings from passive analysis
    ssti_findings = analysis_results.get("ssti_surface_detector", [])

    for item in ssti_findings:
        url = str(item.get("url", "")).strip()
        if not url or is_low_value_endpoint(url):
            continue
        endpoint_key = str(item.get("endpoint_key") or endpoint_signature(url))
        if endpoint_key in seen_patterns:
            continue
        seen_patterns.add(endpoint_key)

        detected_engines = list(item.get("detected_engines", []))
        signals = list(item.get("signals", []))
        score = int(item.get("score", 0))

        # Check for auth flow endpoints (higher risk for SSTI)
        if is_auth_flow_endpoint(url):
            signals.append("auth_flow_endpoint")
            score += 2

        # Score based on number of detected engines
        engine_score = len(detected_engines) * 3
        score += engine_score

        # Check for template-relevant parameters
        template_params = item.get("template_parameters", [])
        if template_params:
            signals.append("template_relevant_params")
            score += len(template_params) * 2

        # Check for SSTI error patterns
        error_patterns = item.get("error_patterns", [])
        if error_patterns:
            signals.append("ssti_error_patterns")
            score += len(error_patterns) * 4

        # Determine validation state
        validation_state = "passive_only"
        if detected_engines and (template_params or error_patterns):
            validation_state = "active_ready"
            score += 5
        elif detected_engines:
            score += 2

        # Calculate confidence
        confidence = normalized_confidence(
            base=0.45,
            score=score,
            signals=signals,
            cap=0.90,
        )

        # Determine severity
        if len(detected_engines) >= 2 or error_patterns:
            severity = "high"
        elif detected_engines and template_params:
            severity = "medium"
        else:
            severity = "low"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": str(item.get("endpoint_type", "GENERAL")),
                "score": score,
                "severity": severity,
                "signals": sorted(set(signals)),
                "detected_engines": sorted(set(detected_engines)),
                "confidence": round(confidence, 2),
                "validation_state": validation_state,
                "template_parameters": template_params,
                "hint_message": f"SSTI surface detected on {url}. Engines: {', '.join(detected_engines) if detected_engines else 'review recommended'}. Test with safe template payloads.",
            }
        )

    findings.sort(key=lambda x: (-x["score"], -x["confidence"], x["url"]))
    return findings[:50]


def validate(target: dict[str, Any], context: dict[str, Any]) -> ValidationResult:
    """Validate SSTI vulnerability with passive analysis and active testing.

    Performs passive analysis of existing responses for SSTI indicators,
    then actively sends template injection payloads to identified endpoints
    to test for Jinja2, Twig, Freemarker, Velocity, ERB, and other engines.

    Args:
        target: Target dict with url and metadata.
        context: Validation context with analysis_results and http_client.

    Returns:
        ValidationResult with SSTI assessment.
    """
    analysis_results = context.get("analysis_results") if isinstance(context, dict) else {}
    analysis_results = analysis_results if isinstance(analysis_results, dict) else {}
    http_client = context.get("http_client") if isinstance(context, dict) else None

    passive_findings = validate_ssti_candidates(analysis_results)

    if not passive_findings:
        return to_validation_result(
            {"url": target.get("url", ""), "status": "no_ssti_signals"},
            validator="ssti",
            category="ssti",
        )

    top_finding = passive_findings[0]
    target_url = top_finding.get("url", target.get("url", ""))
    validation_state = top_finding.get("validation_state", "passive_only")

    active_result: dict[str, Any] = {"status": "skipped", "reason": "not_active_ready"}

    if validation_state == "active_ready" and http_client:
        active_result = _active_ssti_test(target_url, http_client)

    active_status = active_result.get("status", "skipped")
    eval_count = active_result.get("evaluations_count", 0)
    error_count = active_result.get("errors_count", 0)
    engines_detected = active_result.get("engines_detected", [])
    math_evaluations = active_result.get("math_evaluations", [])
    template_errors = active_result.get("template_errors", [])
    code_exec_indicators = active_result.get("code_execution_indicators", [])

    base_confidence = top_finding.get("confidence", 0.45)
    bonuses: list[float] = []

    if active_status == "confirmed":
        bonuses.append(0.30)
    elif active_status == "potential":
        bonuses.append(0.15)
    elif active_status == "not_vulnerable":
        bonuses.append(-0.10)

    if eval_count >= 2:
        bonuses.append(0.15)
    elif eval_count >= 1:
        bonuses.append(0.08)

    if error_count >= 3:
        bonuses.append(0.10)
    elif error_count >= 1:
        bonuses.append(0.05)

    if engines_detected:
        bonuses.append(0.05 * min(len(engines_detected), 3))

    if code_exec_indicators:
        bonuses.append(0.12)

    if validation_state == "active_ready":
        bonuses.append(0.08)

    passive_engines = top_finding.get("detected_engines", [])
    if passive_engines:
        bonuses.append(0.04 * min(len(passive_engines), 3))

    confidence = round(min(max(base_confidence + sum(bonuses), 0.10), 0.98), 2)

    if active_status == "confirmed":
        final_status = "confirmed"
        severity = "critical"
    elif active_status == "potential" or (
        error_count > 0 and top_finding.get("severity") == "high"
    ):
        final_status = "potential"
        severity = "high"
    elif eval_count > 0:
        final_status = "potential"
        severity = "high"
    elif error_count > 0:
        final_status = "potential"
        severity = "medium"
    else:
        final_status = "not_confirmed"
        severity = "low"

    edge_case_notes = []
    if active_status == "skipped":
        edge_case_notes.append(
            "Active testing was skipped — no HTTP client or endpoint not active-ready."
        )
    if code_exec_indicators:
        edge_case_notes.append(
            f"Code execution indicators detected ({len(code_exec_indicators)}) — immediate remediation recommended."
        )
    if engines_detected:
        edge_case_notes.append(
            f"Template engines detected in response: {', '.join(engines_detected)}."
        )

    evidence = {
        "passive_signals": top_finding.get("signals", []),
        "detected_engines_passive": top_finding.get("detected_engines", []),
        "template_parameters": top_finding.get("template_parameters", []),
        "active_status": active_status,
        "evaluations_count": eval_count,
        "errors_count": error_count,
        "engines_detected": engines_detected,
        "math_evaluations": math_evaluations,
        "template_errors": template_errors,
        "code_execution_indicators": code_exec_indicators,
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

    return to_validation_result(result_item, validator="ssti", category="ssti")

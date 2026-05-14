"""Deserialization Language-Specific Probe - Active test for insecure deserialization.

Tests endpoints for insecure deserialization vulnerabilities across multiple
languages and frameworks including Java, Python, PHP, Ruby, and .NET.
Sends crafted payloads and analyzes responses for execution indicators.

This package modularizes the deserialization probe into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from src.analysis.helpers import endpoint_signature, normalize_headers

from ._constants import DESERIALIZATION_PROBE_SPEC
from ._helpers import (
    build_finding,
    detect_deserialization_errors,
    detect_serialization_markers,
    detect_stack_traces,
    detect_vulnerable_response,
    get_payloads,
    has_serialization_params,
    is_serialization_endpoint,
    safe_request,
)

__all__ = ["deserialization_probe", "DESERIALIZATION_PROBE_SPEC"]


def deserialization_probe(
    urls: set[str],
    responses: list[dict[str, Any]],
    response_cache: Any = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Test endpoints for insecure deserialization vulnerabilities."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    probed_count = 0

    response_by_url: dict[str, dict[str, Any]] = {}
    for resp in responses:
        resp_url = str(resp.get("url", "")).strip()
        if resp_url:
            response_by_url[resp_url] = resp

    candidate_urls: list[tuple[str, dict[str, Any], list[str]]] = []

    for resp in responses:
        url = str(resp.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        content_type = str(resp.get("content_type", ""))
        body = str(resp.get("body_text") or "")[:8000]
        _ = normalize_headers(resp)

        is_serial_endpoint = is_serialization_endpoint(url, content_type)
        serial_params = has_serialization_params(url)
        body_markers = detect_serialization_markers(body)

        signals = []
        if is_serial_endpoint:
            signals.append("serialization_endpoint_pattern")
        if serial_params:
            signals.extend(f"serial_param:{p}" for p in serial_params)
        if body_markers:
            signals.extend(body_markers)

        if not signals:
            continue

        candidate_urls.append((url, resp, signals))

    for url in sorted({u for u, _, _ in candidate_urls}):
        if probed_count >= limit:
            break

        matching = [(u, r, s) for u, r, s in candidate_urls if u == url]
        if not matching:
            continue

        _, base_resp, base_signals = matching[0]
        base_status = base_resp.get("status_code")
        content_type = str(base_resp.get("content_type", ""))
        body = str(base_resp.get("body_text") or "")[:8000]

        body_markers = detect_serialization_markers(body)
        deser_errors = detect_deserialization_errors(body)
        stack_traces = detect_stack_traces(body)

        detection_signals = list(base_signals)
        if body_markers:
            detection_signals.extend(body_markers)
        if deser_errors:
            detection_signals.extend(deser_errors)
        if stack_traces:
            detection_signals.extend(stack_traces)

        if len(detection_signals) >= 2 or any(
            "serialization_marker" in s for s in detection_signals
        ):
            severity = "high" if body_markers else "medium"
            title = f"Deserialization surface detected: {url}"
            explanation = (
                f"Endpoint '{url}' shows indicators of serialization/deserialization "
                f"processing. Detected signals: {', '.join(detection_signals[:8])}. "
                f"This endpoint should be tested with crafted serialized payloads."
            )
            if deser_errors:
                explanation += f" Deserialization errors found: {', '.join(deser_errors[:3])}."

            finding = build_finding(
                url=url,
                severity=severity,
                title=title,
                category="deserialization",
                signals=detection_signals[:12],
                evidence={
                    "content_type": content_type,
                    "serialization_markers": body_markers,
                    "deserialization_errors": deser_errors[:5],
                    "stack_traces": stack_traces[:3],
                    "base_status": base_status,
                },
                explanation=explanation,
                status_code=base_status,
            )
            findings.append(finding)

    for url, resp, base_signals in candidate_urls:
        if probed_count >= limit:
            break
        if not url.startswith(("http://", "https://")):
            continue

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        serial_params = has_serialization_params(url)

        payloads = get_payloads()

        for lang, payload, content_type in payloads:
            probe_signals = list(base_signals)
            probe_signals.append(f"probe_language:{lang}")

            if serial_params:
                for param in serial_params[:2]:
                    mutated_qs = dict(query_params)
                    mutated_qs[param] = [payload.decode("utf-8", errors="replace")]
                    mutated_query = urlencode(mutated_qs, doseq=True)
                    mutated_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{mutated_query}"

                    probe = safe_request(mutated_url, method="GET", timeout=8)
                    probed_count += 1

                    if detect_vulnerable_response(probe.get("body", "")):
                        finding = build_finding(
                            url=url,
                            severity="critical",
                            title=f"Possible deserialization code execution ({lang}): {url}",
                            category="deserialization",
                            signals=probe_signals
                            + ["vulnerable_response_detected", f"payload:{lang}"],
                            evidence={
                                "language": lang,
                                "parameter": param,
                                "mutated_url": mutated_url,
                                "probe_status": probe.get("status"),
                                "probe_elapsed": probe.get("elapsed"),
                                "response_preview": probe.get("body", "")[:500],
                            },
                            explanation=(
                                f"Endpoint '{url}' returned a response indicating "
                                f"possible payload execution with {lang} deserialization "
                                f"payload sent via parameter '{param}'. "
                                f"Status: {probe.get('status')}, "
                                f"Response time: {probe.get('elapsed', 0):.2f}s."
                            ),
                            status_code=probe.get("status"),
                        )
                        findings.append(finding)
                    else:
                        probe_errors = detect_deserialization_errors(probe.get("body", ""))
                        probe_traces = detect_stack_traces(probe.get("body", ""))
                        if probe_errors or probe_traces:
                            finding = build_finding(
                                url=url,
                                severity="high",
                                title=f"Deserialization error response ({lang}): {url}",
                                category="deserialization",
                                signals=probe_signals + probe_errors[:3] + probe_traces[:3],
                                evidence={
                                    "language": lang,
                                    "parameter": param,
                                    "mutated_url": mutated_url,
                                    "probe_status": probe.get("status"),
                                    "probe_elapsed": probe.get("elapsed"),
                                    "errors": probe_errors[:5],
                                    "traces": probe_traces[:3],
                                },
                                explanation=(
                                    f"Endpoint '{url}' returned deserialization errors "
                                    f"when probed with {lang} payload via parameter "
                                    f"'{param}'. This confirms the endpoint processes "
                                    f"serialized data and may be vulnerable to "
                                    f"insecure deserialization attacks."
                                ),
                                status_code=probe.get("status"),
                            )
                            findings.append(finding)

    findings.sort(
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item.get("severity", "low"), 4),
            -item.get("score", 0),
            item.get("url", ""),
        )
    )
    return findings[:limit]

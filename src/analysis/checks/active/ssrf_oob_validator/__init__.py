"""SSRF Out-of-Band Validator - Active probe for Server-Side Request Forgery.

Performs out-of-band SSRF testing using callback/interaction detection,
internal IP probing, DNS-based detection, protocol variations, and
URL encoding bypasses. Checks responses for internal data leakage.

This package modularizes the SSRF validator into separate files
for better maintainability and AI-agent editability.
"""

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from src.analysis.helpers import endpoint_signature

from ._constants import (
    DNS_CALLBACK_RE,
    ENCODING_BYPASSES,
    INTERNAL_TARGETS,
    PROTOCOL_PAYLOADS,
    SSRF_OOB_VALIDATOR_SPEC,
)
from ._helpers import (
    build_finding,
    check_cloud_metadata,
    check_internal_errors,
    check_internal_leakage,
    find_ssrf_params,
    safe_request,
)

__all__ = ["ssrf_oob_validator", "SSRF_OOB_VALIDATOR_SPEC", "DNS_CALLBACK_RE", "ENCODING_BYPASSES"]


def ssrf_oob_validator(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 15,
) -> list[dict[str, Any]]:
    """Test endpoints for SSRF vulnerabilities using out-of-band detection."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    probed_count = 0

    response_by_url: dict[str, dict[str, Any]] = {}
    for resp in responses:
        resp_url = str(resp.get("url", "")).strip()
        if resp_url:
            response_by_url[resp_url] = resp

    candidate_endpoints: list[tuple[str, list[tuple[str, str]], dict[str, Any]]] = []

    for resp in responses:
        url = str(resp.get("url", "")).strip()
        if not url:
            continue
        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        ssrf_params = find_ssrf_params(url)
        if ssrf_params:
            candidate_endpoints.append((url, ssrf_params, resp))

    for url in sorted({u for u, _, _ in candidate_endpoints}):
        if probed_count >= limit:
            break

        matching = [(u, p, r) for u, p, r in candidate_endpoints if u == url]
        if not matching:
            continue

        base_url, base_params, base_resp = matching[0]
        base_status = base_resp.get("status_code")

        findings.append(
            build_finding(
                url=url,
                severity="medium",
                title=f"SSRF-susceptible parameters detected: {url}",
                category="ssrf",
                signals=[f"ssrf_param:{name}" for name, _ in base_params],
                evidence={
                    "parameters": [{"name": n, "value_preview": v[:80]} for n, v in base_params],
                    "base_status": base_status,
                },
                explanation=(
                    f"Endpoint '{url}' contains parameters that appear susceptible "
                    f"to SSRF: {', '.join(n for n, _ in base_params)}. "
                    f"These parameters accept URL-like or host-like values and should "
                    f"be tested with internal address payloads."
                ),
                status_code=base_status,
            )
        )

    for url, ssrf_params, base_resp in candidate_endpoints:
        if probed_count >= limit:
            break
        if not url.startswith(("http://", "https://")):
            continue

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        base_status = base_resp.get("status_code")

        baseline_probe = safe_request(url, timeout=8)
        baseline_status = baseline_probe.get("status", 0)
        baseline_elapsed = baseline_probe.get("elapsed", 0)

        for param_name, _ in ssrf_params:
            if probed_count >= limit:
                break

            for target in INTERNAL_TARGETS[:8]:
                mutated_qs = dict(query_params)
                mutated_qs[param_name] = [target]
                mutated_query = urlencode(mutated_qs, doseq=True)
                mutated_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{mutated_query}"

                probe = safe_request(mutated_url, timeout=8)
                probed_count += 1
                probe_status = probe.get("status", 0)
                probe_elapsed = probe.get("elapsed", 0)
                probe_body = probe.get("body", "")

                signals = [f"ssrf_param:{param_name}", f"internal_target:{target}"]

                cloud_matches = check_cloud_metadata(probe_body)
                if cloud_matches:
                    signals.extend(cloud_matches[:5])
                    signals.append("cloud_metadata_access")
                    findings.append(
                        build_finding(
                            url=url,
                            severity="critical",
                            title=f"Cloud metadata access via SSRF: {url}",
                            category="ssrf",
                            signals=signals,
                            evidence={
                                "parameter": param_name,
                                "payload": target,
                                "mutated_url": mutated_url,
                                "probe_status": probe_status,
                                "probe_elapsed": probe_elapsed,
                                "cloud_metadata_indicators": cloud_matches[:8],
                                "response_preview": probe_body[:1000],
                                "baseline_status": baseline_status,
                                "baseline_elapsed": baseline_elapsed,
                            },
                            explanation=(
                                f"SSRF probe to '{url}' with parameter '{param_name}' "
                                f"set to '{target}' returned cloud metadata indicators. "
                                f"This indicates the server-side application made a request "
                                f"to the cloud metadata service. "
                                f"Status: {probe_status}, Response time: {probe_elapsed:.2f}s."
                            ),
                            status_code=probe_status,
                        )
                    )
                    continue

                internal_leaks = check_internal_leakage(probe_body)
                if internal_leaks:
                    signals.extend(internal_leaks[:5])
                    findings.append(
                        build_finding(
                            url=url,
                            severity="high",
                            title=f"Internal network information leakage via SSRF: {url}",
                            category="ssrf",
                            signals=signals,
                            evidence={
                                "parameter": param_name,
                                "payload": target,
                                "mutated_url": mutated_url,
                                "probe_status": probe_status,
                                "probe_elapsed": probe_elapsed,
                                "internal_leak_indicators": internal_leaks[:8],
                                "response_preview": probe_body[:1000],
                                "baseline_status": baseline_status,
                            },
                            explanation=(
                                f"SSRF probe to '{url}' with parameter '{param_name}' "
                                f"set to '{target}' returned internal network information. "
                                f"Status: {probe_status}, Response time: {probe_elapsed:.2f}s."
                            ),
                            status_code=probe_status,
                        )
                    )
                    continue

                internal_errors = check_internal_errors(probe_body)
                if internal_errors:
                    signals.extend(internal_errors[:5])
                    signals.append("internal_error_response")
                    findings.append(
                        build_finding(
                            url=url,
                            severity="high",
                            title=f"Internal network access confirmed via SSRF: {url}",
                            category="ssrf",
                            signals=signals,
                            evidence={
                                "parameter": param_name,
                                "payload": target,
                                "mutated_url": mutated_url,
                                "probe_status": probe_status,
                                "probe_elapsed": probe_elapsed,
                                "internal_error_indicators": internal_errors[:5],
                                "response_preview": probe_body[:1000],
                                "baseline_status": baseline_status,
                            },
                            explanation=(
                                f"SSRF probe to '{url}' with parameter '{param_name}' "
                                f"set to '{target}' returned errors revealing internal "
                                f"network topology. Status: {probe_status}."
                            ),
                            status_code=probe_status,
                        )
                    )
                    continue

                if probe_status != baseline_status and probe_status != 0:
                    signals.append("status_code_change")
                    findings.append(
                        build_finding(
                            url=url,
                            severity="medium",
                            title=f"SSRF parameter confirmed via status change: {url}",
                            category="ssrf",
                            signals=signals,
                            evidence={
                                "parameter": param_name,
                                "payload": target,
                                "mutated_url": mutated_url,
                                "probe_status": probe_status,
                                "baseline_status": baseline_status,
                                "probe_elapsed": probe_elapsed,
                                "baseline_elapsed": baseline_elapsed,
                                "response_preview": probe_body[:500],
                            },
                            explanation=(
                                f"SSRF probe to '{url}' with parameter '{param_name}' "
                                f"set to '{target}' caused a status code change from "
                                f"{baseline_status} to {probe_status}, suggesting the "
                                f"server processed the internal target."
                            ),
                            status_code=probe_status,
                        )
                    )
                    continue

                if probe_elapsed > baseline_elapsed * 3 and probe_elapsed > 5:
                    signals.append("response_time_anomaly")
                    findings.append(
                        build_finding(
                            url=url,
                            severity="medium",
                            title=f"SSRF time-based detection: {url}",
                            category="ssrf",
                            signals=signals,
                            evidence={
                                "parameter": param_name,
                                "payload": target,
                                "mutated_url": mutated_url,
                                "probe_elapsed": probe_elapsed,
                                "baseline_elapsed": baseline_elapsed,
                                "probe_status": probe_status,
                                "response_preview": probe_body[:500],
                            },
                            explanation=(
                                f"SSRF probe to '{url}' with parameter '{param_name}' "
                                f"set to '{target}' caused a significant response time "
                                f"increase ({baseline_elapsed:.2f}s -> {probe_elapsed:.2f}s), "
                                f"suggesting the server attempted to reach the internal target."
                            ),
                            status_code=probe_status,
                        )
                    )

            for proto_payload in PROTOCOL_PAYLOADS[:4]:
                if probed_count >= limit:
                    break
                mutated_qs = dict(query_params)
                mutated_qs[param_name] = [proto_payload]
                mutated_query = urlencode(mutated_qs, doseq=True)
                mutated_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{mutated_query}"

                probe = safe_request(mutated_url, timeout=8)
                probed_count += 1

                proto_errors = check_internal_errors(probe.get("body", ""))
                if proto_errors:
                    signals = [f"ssrf_param:{param_name}", f"protocol_payload:{proto_payload[:30]}"]
                    signals.extend(proto_errors[:3])
                    findings.append(
                        build_finding(
                            url=url,
                            severity="high",
                            title=f"Protocol handler SSRF confirmed: {url}",
                            category="ssrf",
                            signals=signals,
                            evidence={
                                "parameter": param_name,
                                "payload": proto_payload,
                                "mutated_url": mutated_url,
                                "probe_status": probe.get("status"),
                                "probe_elapsed": probe.get("elapsed"),
                                "protocol_error_indicators": proto_errors[:5],
                                "response_preview": probe.get("body", "")[:1000],
                            },
                            explanation=(
                                f"SSRF probe to '{url}' with protocol payload "
                                f"'{proto_payload}' in parameter '{param_name}' "
                                f"returned error indicating protocol handler processing."
                            ),
                            status_code=probe.get("status"),
                        )
                    )

    findings.sort(
        key=lambda item: (-item.get("score", 0), -item.get("confidence", 0), item.get("url", ""))
    )
    return findings[:limit]

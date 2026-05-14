"""HTTP method override probe."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    is_noise_url,
)
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._diff_utils import variant_diff_summary


def http_method_override_probe(
    priority_urls: list[str], response_cache: ResponseCache, limit: int = 12
) -> list[dict[str, Any]]:
    """Probe for HTTP method override vulnerabilities via headers."""
    findings: list[dict[str, Any]] = []
    override_headers = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-HTTP-Method-Override", "PUT"),
        ("X-HTTP-Method-Override", "PATCH"),
        ("X-Method-Override", "DELETE"),
        ("X-Original-HTTP-Method", "DELETE"),
        ("X-HTTP-Method", "DELETE"),
        ("X-HTTP-Method-Override", "HEAD"),
        ("X-HTTP-Method-Override", "OPTIONS"),
        ("X-HTTP-Method-Override", "CONNECT"),
        ("X-HTTP-Method-Override", "TRACE"),
        ("X-Method-Override", "PUT"),
        ("X-Method-Override", "PATCH"),
    ]
    for url in priority_urls:
        if len(findings) >= limit:
            break
        if not url or is_noise_url(url):
            continue
        if classify_endpoint(url) == "STATIC":
            continue
        baseline = response_cache.get(url)
        if not baseline:
            continue
        baseline_status = int(baseline.get("status_code") or 0)
        if baseline_status >= 400 and baseline_status != 405:
            continue
        observations = []
        for header_name, header_value in override_headers:
            mutated = response_cache.request(
                url,
                headers={"Cache-Control": "no-cache", header_name: header_value},
            )
            if not mutated:
                continue
            mutated_status = int(mutated.get("status_code") or 0)
            diff = variant_diff_summary(baseline, mutated)
            method_override_detected = (
                diff["status_changed"]
                or diff["body_similarity"] < 0.9
                or (
                    baseline_status < 400
                    and mutated_status >= 400
                    and mutated_status not in (405, 501)
                )
                or (baseline_status == 405 and mutated_status < 400)
            )
            if method_override_detected:
                observations.append(
                    {
                        "header": header_name,
                        "override_value": header_value,
                        "baseline_status": baseline_status,
                        "override_status": mutated_status,
                        "body_similarity": diff["body_similarity"],
                        "status_changed": diff["status_changed"],
                        "content_changed": diff["content_changed"],
                    }
                )
        parsed = urlparse(url)
        raw_query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for method_value in ("DELETE", "PUT", "PATCH"):
            tampered_pairs = [*raw_query_pairs, ("_method", method_value)]
            tampered_url = normalize_url(
                urlparse(url)._replace(query=urlencode(tampered_pairs, doseq=True)).geturl()
            )
            mutated = response_cache.request(
                tampered_url,
                headers={"Cache-Control": "no-cache"},
            )
            if mutated:
                mutated_status = int(mutated.get("status_code") or 0)
                diff = variant_diff_summary(baseline, mutated)
                if diff["status_changed"] or diff["body_similarity"] < 0.9:
                    observations.append(
                        {
                            "header": "_method_query_param",
                            "override_value": method_value,
                            "baseline_status": baseline_status,
                            "override_status": mutated_status,
                            "body_similarity": diff["body_similarity"],
                            "status_changed": diff["status_changed"],
                            "content_changed": diff["content_changed"],
                            "mutated_url": tampered_url,
                        }
                    )
        if observations:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "observations": observations[:6],
                    "method_override_detected": len(observations) >= 2,
                    "signals": sorted(
                        {
                            "http_method_override_probe",
                            "status_divergence"
                            if any(o["status_changed"] for o in observations)
                            else "",
                            "content_divergence"
                            if any(o["content_changed"] for o in observations)
                            else "",
                            "multi_header_consistent" if len(observations) >= 2 else "",
                            "method_param_injection"
                            if any(o.get("header") == "_method_query_param" for o in observations)
                            else "",
                            "auth_bypass_via_method"
                            if any(
                                o["baseline_status"] < 400
                                and o["override_status"] < 400
                                and o["override_status"] != baseline_status
                                for o in observations
                            )
                            else "",
                        }
                        - {""}
                    ),
                }
            )
    findings.sort(
        key=lambda item: (
            not item["method_override_detected"],
            -len(item["observations"]),
            item["url"],
        )
    )
    return findings[:limit]

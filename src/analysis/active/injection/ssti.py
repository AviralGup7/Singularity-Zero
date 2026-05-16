"""SSTI active probe."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity
from ._patterns import SSTI_ERROR_RE


def ssti_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test parameters with template injection payloads.

    Sends payloads like {{7*7}}, ${7*7}, <%= 7*7 %> to parameters.
    Checks responses for 49 (result of 7*7) and template error messages.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of SSTI findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    ssti_payloads = [
        ("jinja2_dollar", "{{7*7}}"),
        ("jinja2_add", "{{7+7}}"),
        ("erb_interpolation", "<%= 7*7 %>"),
        ("erb_hash", "#{7*7}"),
        ("freemarker", "${7*7}"),
        ("twig", "{{config}}"),
        ("velocity", "#set($x=7)${x}"),
        ("mustache", "{{#7*7}}"),
        ("ejs", "<%= 7*7 %>"),
        ("handlebars", "{{#equals 7 7}}49{{/equals}}"),
    ]

    template_relevant_params = {
        "template",
        "view",
        "render",
        "tpl",
        "page",
        "layout",
        "content",
        "body",
        "html",
        "text",
        "name",
        "title",
        "subject",
        "message",
        "comment",
        "description",
        "q",
        "query",
        "search",
    }

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        template_params = [
            (i, pn, pv)
            for i, (pn, pv) in enumerate(query_pairs)
            if pn.lower() in template_relevant_params
        ]
        for idx, param_name, _param_value in template_params:
            if len(url_probes) >= 2:
                break
            for payload_name, payload_value in ssti_payloads:
                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={
                        "Cache-Control": "no-cache",
                        "X-SSTI-Probe": "1",
                    },
                )
                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)

                issues_for_hit: list[str] = []

                if "49" in body and "7*7" not in body:
                    issues_for_hit.append("ssti_arithmetic_reflection")
                elif "14" in body and payload_value == "{{7+7}}" and "7+7" not in body:
                    issues_for_hit.append("ssti_arithmetic_reflection")
                elif SSTI_ERROR_RE.search(body):
                    issues_for_hit.append("ssti_error_pattern")
                elif status == 500 and len(body) > 50:
                    issues_for_hit.append("ssti_template_syntax")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": param_name,
                            "payload": payload_value,
                            "payload_type": payload_name,
                            "status_code": status,
                            "issues": issues_for_hit,
                        }
                    )
                    break

        if url_probes:
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_key,
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": url_issues,
                    "probes": url_probes,
                    "confidence": probe_confidence(url_issues),
                    "severity": probe_severity(url_issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]

"""Safe SQL injection probes."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.sqli_signals import SQL_ERROR_RE, SQL_PARAM_NAMES

from ._confidence import probe_confidence, probe_severity

SQLI_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("'", "single_quote"),
    ('"', "double_quote"),
    ("1 OR 1=1", "numeric_boolean"),
    ("1' OR '1'='1", "string_boolean"),
    ("1; SELECT 1--", "stacked_query"),
)


def sqli_safe_probe(
    priority_urls: list[dict[str, Any]] | list[str],
    response_cache: Any,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Send safe SQLi test payloads to SQL-relevant parameters and check for error responses. (Fix Audit #8, #23)"""
    if response_cache is None:
        return []

    from src.recon.common import normalize_url

    findings: list[dict[str, Any]] = []

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break

        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        parsed = urlparse(url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not query_pairs or classify_endpoint(url) == "STATIC":
            continue

        sql_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in SQL_PARAM_NAMES
        ]
        if not sql_params:
            continue

        url_findings: list[dict[str, Any]] = []

        for idx, param_name, _param_value in sql_params:
            for test_value, payload_type in SQLI_PAYLOADS:
                updated = list(query_pairs)
                updated[idx] = (param_name, test_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={"Cache-Control": "no-cache", "X-SQLi-Probe": "1"},
                )
                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)
                match = SQL_ERROR_RE.search(body)

                if match:
                    url_findings.append(
                        {
                            "parameter": param_name,
                            "payload": test_value,
                            "payload_type": payload_type,
                            "status_code": status,
                            "error_pattern": match.group(0),
                            "error_context": body[max(0, match.start() - 60) : match.end() + 60],
                        }
                    )
                    break  # Stop after first SQL error for this param

        if url_findings:
            issues = ["sqli_error_response"]
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": issues,
                    "probes": url_findings,
                    "confidence": probe_confidence(issues),
                    "severity": probe_severity(issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings

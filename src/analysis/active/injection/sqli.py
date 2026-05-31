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
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Send low-impact SQLi payloads to SQL-relevant query parameters."""
    if response_cache is None:
        return []

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

        probe_hits: list[dict[str, Any]] = []
        for index, (param_name, _param_value) in enumerate(query_pairs):
            if param_name.lower() not in SQL_PARAM_NAMES:
                continue

            for payload, payload_type in SQLI_PAYLOADS:
                updated = list(query_pairs)
                updated[index] = (param_name, payload)
                mutated_url = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))

                response = response_cache.request(
                    mutated_url,
                    headers={"Cache-Control": "no-cache", "X-SQLi-Probe": "1"},
                )
                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                match = SQL_ERROR_RE.search(body)
                if not match:
                    continue

                probe_hits.append(
                    {
                        "parameter": param_name,
                        "payload_type": payload_type,
                        "payload": payload,
                        "mutated_url": mutated_url,
                        "status_code": response.get("status_code"),
                        "error_pattern": match.group(0),
                        "error_context": body[max(0, match.start() - 60) : match.end() + 60],
                    }
                )
                break

        if probe_hits:
            issues = ["sqli_error_response"]
            findings.append(
                {
                    "url": url,
                    "endpoint_key": endpoint_signature(url),
                    "endpoint_base_key": endpoint_base_key(url),
                    "endpoint_type": classify_endpoint(url),
                    "issues": issues,
                    "probes": probe_hits,
                    "confidence": probe_confidence(issues),
                    "severity": probe_severity(issues),
                }
            )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:limit]

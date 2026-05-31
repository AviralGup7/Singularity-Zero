"""Passive SQL injection signal detector."""

from typing import Any
from urllib.parse import parse_qsl, urlparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.sqli_signals import SQL_ERROR_RE, SQL_PARAM_NAMES


def sql_error_exposure_detector(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect SQL error disclosures in already captured responses."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for response in responses:
        url = str(response.get("url", "") or "").strip()
        if not url:
            continue

        body = str(response.get("body_text", "") or "")[:12000]
        match = SQL_ERROR_RE.search(body)
        if not match:
            continue

        query_names = sorted(
            {name.lower() for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)}
        )
        sql_params = sorted(set(query_names) & SQL_PARAM_NAMES)
        key = (url, match.group(0).lower())
        if key in seen:
            continue
        seen.add(key)

        signals = ["sql_error_disclosure"]
        if sql_params:
            signals.extend(f"param:{name}" for name in sql_params)

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_signature(url),
                "endpoint_base_key": endpoint_base_key(url),
                "endpoint_type": classify_endpoint(url),
                "status_code": response.get("status_code"),
                "indicator": "sql_error_disclosure",
                "issues": ["sql_error_disclosure"],
                "signals": signals,
                "parameters": sql_params,
                "error_pattern": match.group(0),
                "error_context": body[max(0, match.start() - 80) : match.end() + 80],
                "confidence": 0.88 if sql_params else 0.74,
                "severity": "high" if sql_params else "medium",
            }
        )

    findings.sort(key=lambda item: (-item["confidence"], item["url"]))
    return findings[:80]

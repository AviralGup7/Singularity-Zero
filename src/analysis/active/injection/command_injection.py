"""Command injection active probe."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity
from ._patterns import CMD_ERROR_RE, CMD_OUTPUT_RE


def command_injection_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """Test command-relevant parameters with command injection payloads.

    Sends payloads like ;id, |whoami, &&echo test to parameters that look
    like they execute commands. Checks responses for command output patterns
    and error messages.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of command injection findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    cmd_param_names = {
        "cmd",
        "exec",
        "command",
        "run",
        "execute",
        "ping",
        "query",
        "process",
        "action",
        "handler",
        "upload",
        "download",
        "import",
        "export",
        "daemon",
        "service",
        "task",
        "job",
        "invoke",
        "shell",
        "system",
        "cgi",
        "func",
        "callback",
    }

    cmd_payloads = [
        ("semicolon_id", ";id"),
        ("pipe_whoami", "|whoami"),
        ("and_echo", "&&echo TESTCMDINJ"),
        ("backtick_id", "`id`"),
        ("dollar_paren", "$(id)"),
        ("pipe_echo", "|echo TESTCMDINJ"),
        ("newline_id", "%0aid"),
        ("encoded_semicolon", "%3Bid"),
    ]

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

        cmd_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in cmd_param_names
        ]
        if not cmd_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, _param_value in cmd_params:
            if len(url_probes) >= 2:
                break
            for payload_name, payload_value in cmd_payloads:
                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={"Cache-Control": "no-cache", "X-CmdInj-Probe": "1"},
                )
                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)

                issues_for_hit: list[str] = []

                if CMD_OUTPUT_RE.search(body):
                    issues_for_hit.append("command_injection_output_reflection")
                elif "TESTCMDINJ" in body:
                    issues_for_hit.append("command_injection_output_reflection")
                elif CMD_ERROR_RE.search(body):
                    issues_for_hit.append("command_injection_error_pattern")

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

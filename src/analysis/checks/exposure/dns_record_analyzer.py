"""DNS Record Analyzer - Passive exposure check for DNS misconfiguration signals.

Analyzes response bodies, headers, and URLs for domain references,
attempts DNS resolution, checks for dangling CNAMEs pointing to
unclaimed cloud services, and detects CDN/WAF provider domains.
"""

import re
import socket
from typing import Any

from src.analysis.helpers import (
    classify_endpoint,
    endpoint_base_key,
    endpoint_signature,
    normalize_headers,
)
from src.analysis.helpers.scoring import severity_score
from src.analysis.plugins import AnalysisPluginSpec

DNS_RECORD_ANALYZER_SPEC = AnalysisPluginSpec(
    key="dns_record_analyzer",
    label="DNS Record Analyzer",
    description="Check for DNS misconfiguration signals, dangling CNAMEs, third-party domain exposure, and CDN/WAF provider detection.",
    group="exposure",
    slug="dns_record_analyzer",
    enabled_by_default=True,
)

# Cloud provider CNAME patterns for dangling subdomain takeover detection
DANGLING_CNAME_PATTERNS: dict[str, list[str]] = {
    "github_pages": [".github.io"],
    "heroku": [".herokuapp.com"],
    "azure_websites": [".azurewebsites.net"],
    "azure_cloudapp": [".cloudapp.net"],
    "azure_frontdoor": [".azurefd.net"],
    "aws_s3": [".s3-website", ".s3-website-", ".s3."],
    "aws_cloudfront": [".cloudfront.net"],
    "aws_elasticbeanstalk": [".elasticbeanstalk.com"],
    "shopify": [".myshopify.com"],
    "desk": [".desk.com"],
    "zendesk": [".zendesk.com"],
}

# CDN/WAF provider domain patterns
CDN_WAF_PATTERNS: dict[str, list[str]] = {
    "cloudflare": [".cloudflare.com", ".cloudflare.net", "cloudflare-", "cdn.cloudflare.net"],
    "akamai": [".akamai.net", ".akamaiedge.net", ".akamaihd.net", ".akamaized.net", "edgekey.net"],
    "fastly": [".fastly.net", ".fastlylb.net", "fastly-", ".fastly.com"],
    "aws_cloudfront_cdn": [".cloudfront.net"],
    "azure_cdn": [".azureedge.net", ".msecnd.net"],
    "google_cloud_cdn": [".googleusercontent.com", ".gstatic.com"],
    "incapsula": [".incapdns.net"],
    "sucuri": [".sucuri.net"],
    "imperva": [".imperva.com", ".incapsula.com"],
}

# Common domain extraction patterns
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|dev|app|xyz|info|biz|us|uk|de|fr|jp|cn|in|br|ru|au|ca|it|nl|se|no|fi|es|pt|pl|cz|at|ch|be|dk|ie|nz|za|sg|hk|tw|kr|mx|ar|cl|co\.uk|co\.jp|co\.in|com\.au|com\.br|com\.cn|com\.mx|com\.sg|com\.tw|com\.hk|net\.au|org\.uk|ac\.uk|gov\.uk|edu|edu\.cn|edu\.au|gov|mil|int|arpa|onion)\b",
    re.IGNORECASE,
)

# Email-related domain hints for SPF/DMARC analysis
_EMAIL_HINT_RE = re.compile(
    r"(?:spf|dmarc|mx|mail|email|_dmarc|_spf|sendgrid|mailchimp|mandrill|postmark|amazonses|mailgun)",
    re.IGNORECASE,
)

# Parking page indicators
_PARKING_INDICATORS = [
    "parked domain",
    "this domain is parked",
    "domain parking",
    "buy this domain",
    "domain for sale",
    "sedo.com",
    "afternic.com",
    "godaddy.com/parking",
    "bodis.com",
]


def _extract_domains_from_text(text: str, target_domain: str = "") -> set[str]:
    """Extract unique domain names from text content."""
    if not text:
        return set()
    raw_domains: set[str] = set()
    for match in _DOMAIN_RE.finditer(text):
        domain = match.group(0).lower().rstrip(".")
        if domain and len(domain) > 3:
            raw_domains.add(domain)
    if target_domain:
        raw_domains.discard(target_domain.lower())
        raw_domains.discard("www." + target_domain.lower())
    return raw_domains


def _extract_domains_from_headers(headers: dict[str, str]) -> set[str]:
    """Extract domain references from HTTP response headers."""
    domains: set[str] = set()
    header_sources = (
        headers.get("location", ""),
        headers.get("x-forwarded-host", ""),
        headers.get("x-forwarded-server", ""),
        headers.get("x-powered-by", ""),
        headers.get("server", ""),
        headers.get("via", ""),
        headers.get("x-amz-request-id", ""),
        headers.get("x-azure-ref", ""),
        headers.get("link", ""),
        headers.get("content-location", ""),
        headers.get("origin", ""),
        headers.get("access-control-allow-origin", ""),
    )
    for value in header_sources:
        if value:
            domains.update(_extract_domains_from_text(value))
    return domains


def _resolve_domain(domain: str) -> dict[str, Any]:
    """Attempt DNS resolution for a domain."""
    result: dict[str, Any] = {
        "domain": domain,
        "resolves": False,
        "ips": [],
        "error": None,
        "cname_chain": [],
    }
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = list({info[4][0] for info in infos if info[4]})
        if ips:
            result["resolves"] = True
            result["ips"] = ips
    except socket.gaierror as exc:
        result["error"] = str(exc)
    except socket.herror as exc:
        result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _check_dangling_cname(domain: str, resolution: dict[str, Any]) -> list[dict[str, str]]:
    """Check if a domain resolves to a known cloud service that may be unclaimed."""
    findings: list[dict[str, str]] = []
    domain_lower = domain.lower()
    for service, patterns in DANGLING_CNAME_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in domain_lower:
                findings.append(
                    {
                        "service": service,
                        "pattern": pattern,
                        "domain": domain,
                    }
                )
                break
    if not findings and resolution.get("resolves"):
        for ip in resolution.get("ips", []):
            if ip.startswith("185.199.108.") or ip.startswith("185.199.109."):
                findings.append(
                    {
                        "service": "github_pages_ip",
                        "pattern": "185.199.108.0/22",
                        "domain": domain,
                    }
                )
    return findings


def _check_parking_page(domain: str, resolution: dict[str, Any]) -> bool:
    """Check if a domain resolves to a known parking page IP range."""
    if not resolution.get("resolves"):
        return False
    parking_ip_prefixes = (
        "185.53.177.",
        "185.53.178.",
        "185.53.179.",
        "91.195.240.",
        "91.195.241.",
        "103.224.",
        "198.49.23.",
        "198.185.159.",
    )
    for ip in resolution.get("ips", []):
        if any(ip.startswith(prefix) for prefix in parking_ip_prefixes):
            return True
    return False


def _detect_cdn_waf(domain: str) -> list[str]:
    """Detect CDN/WAF provider from domain patterns."""
    providers: list[str] = []
    domain_lower = domain.lower()
    for provider, patterns in CDN_WAF_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in domain_lower:
                if provider not in providers:
                    providers.append(provider)
                break
    return providers


def _is_third_party_domain(domain: str, target_domain: str) -> bool:
    """Check if a domain is third-party relative to the target."""
    if not target_domain:
        return True
    domain_lower = domain.lower().lstrip("www.")
    target_lower = target_domain.lower().lstrip("www.")
    if domain_lower == target_lower:
        return False
    domain_parts = domain_lower.split(".")
    target_parts = target_lower.split(".")
    if len(domain_parts) >= 2 and len(target_parts) >= 2:
        if domain_parts[-2:] == target_parts[-2:]:
            return False
    return True


def _build_finding(
    url: str,
    severity: str,
    title: str,
    category: str,
    signals: list[str],
    evidence: dict[str, Any],
    explanation: str,
    status_code: int | None = None,
) -> dict[str, Any]:
    """Build a standardized finding dict."""
    return {
        "url": url,
        "endpoint_key": endpoint_signature(url),
        "endpoint_base_key": endpoint_base_key(url),
        "endpoint_type": classify_endpoint(url),
        "status_code": status_code,
        "category": category,
        "title": title,
        "severity": severity,
        "confidence": 0.75
        if severity in ("critical", "high")
        else 0.6
        if severity == "medium"
        else 0.5,
        "signals": signals,
        "evidence": evidence,
        "explanation": explanation,
        "score": severity_score(severity),
    }


def dns_record_analyzer(
    urls: set[str],
    responses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Analyze DNS-related signals from URLs and responses.

    Extracts domain names from response bodies and headers, attempts
    DNS resolution, checks for dangling CNAMEs pointing to unclaimed
    cloud services, detects CDN/WAF providers, and tracks third-party
    domain exposure.

    Args:
        urls: Set of URLs discovered during reconnaissance.
        responses: List of HTTP response dicts with url, body_text, headers, etc.

    Returns:
        List of finding dicts with DNS-related security signals.
    """
    findings: list[dict[str, Any]] = []
    seen_dangling: set[str] = set()
    seen_third_party: set[str] = set()
    seen_cdn: set[str] = set()
    seen_parking: set[str] = set()

    response_by_url: dict[str, dict[str, Any]] = {}
    for resp in responses:
        resp_url = str(resp.get("url", "")).strip()
        if resp_url:
            response_by_url[resp_url] = resp

    target_domains: set[str] = set()
    for url in urls:
        try:
            from urllib.parse import urlparse as _up

            host = _up(url).netloc.lower()
            if host:
                target_domains.add(host.lstrip("www."))
        except Exception:
            continue

    primary_target = min(target_domains, key=len) if target_domains else ""

    all_domains: dict[str, set[str]] = {}
    for resp in responses:
        resp_url = str(resp.get("url", "")).strip()
        if not resp_url:
            continue
        body = str(resp.get("body_text") or "")[:50000]
        headers = normalize_headers(resp)
        status_code = resp.get("status_code")
        resp_domains: set[str] = set()
        resp_domains.update(_extract_domains_from_text(body, primary_target))
        resp_domains.update(_extract_domains_from_headers(headers))
        all_domains[resp_url] = resp_domains

        for domain in resp_domains:
            dangling_hits = _check_dangling_cname(domain, {"resolves": False})
            for hit in dangling_hits:
                dedupe_key = f"{domain}:{hit['service']}"
                if dedupe_key not in seen_dangling:
                    seen_dangling.add(dedupe_key)
                    findings.append(
                        _build_finding(
                            url=resp_url,
                            severity="high",
                            title=f"Dangling CNAME candidate: {domain} -> {hit['service']}",
                            category="dns_misconfiguration",
                            signals=[
                                f"dangling_cname:{hit['service']}",
                                f"domain:{domain}",
                                f"pattern:{hit['pattern']}",
                            ],
                            evidence={
                                "domain": domain,
                                "service": hit["service"],
                                "pattern": hit["pattern"],
                                "source_url": resp_url,
                            },
                            explanation=(
                                f"Domain '{domain}' contains a pattern associated with "
                                f"'{hit['service']}'. This may indicate a dangling CNAME "
                                f"that could be claimed by an attacker for subdomain takeover."
                            ),
                            status_code=status_code,
                        )
                    )

            parking = _check_parking_page(domain, {"resolves": False})
            if parking and domain not in seen_parking:
                seen_parking.add(domain)
                findings.append(
                    _build_finding(
                        url=resp_url,
                        severity="medium",
                        title=f"Possible parked domain: {domain}",
                        category="dns_misconfiguration",
                        signals=[f"parked_domain:{domain}"],
                        evidence={
                            "domain": domain,
                            "source_url": resp_url,
                        },
                        explanation=(
                            f"Domain '{domain}' may be a parked domain. "
                            f"Parked domains can indicate abandoned infrastructure "
                            f"or potential takeover targets."
                        ),
                        status_code=status_code,
                    )
                )

            if _EMAIL_HINT_RE.search(domain):
                findings.append(
                    _build_finding(
                        url=resp_url,
                        severity="low",
                        title=f"Email infrastructure domain detected: {domain}",
                        category="dns_misconfiguration",
                        signals=[f"email_domain:{domain}"],
                        evidence={
                            "domain": domain,
                            "source_url": resp_url,
                        },
                        explanation=(
                            f"Domain '{domain}' appears to be related to email "
                            f"infrastructure. Verify SPF, DKIM, and DMARC records "
                            f"are properly configured."
                        ),
                        status_code=status_code,
                    )
                )

            cdn_providers = _detect_cdn_waf(domain)
            for provider in cdn_providers:
                dedupe_key = f"{resp_url}:{provider}:{domain}"
                if dedupe_key not in seen_cdn:
                    seen_cdn.add(dedupe_key)
                    findings.append(
                        _build_finding(
                            url=resp_url,
                            severity="info",
                            title=f"CDN/WAF provider detected: {provider} ({domain})",
                            category="cdn_waf_detection",
                            signals=[f"cdn_provider:{provider}", f"cdn_domain:{domain}"],
                            evidence={
                                "provider": provider,
                                "domain": domain,
                                "source_url": resp_url,
                            },
                            explanation=(
                                f"Domain '{domain}' is associated with "
                                f"CDN/WAF provider '{provider}'."
                            ),
                            status_code=status_code,
                        )
                    )

            if _is_third_party_domain(domain, primary_target):
                dedupe_key = f"{resp_url}:{domain}"
                if dedupe_key not in seen_third_party:
                    seen_third_party.add(dedupe_key)
                    findings.append(
                        _build_finding(
                            url=resp_url,
                            severity="low",
                            title=f"Third-party domain exposure: {domain}",
                            category="third_party_exposure",
                            signals=[f"third_party_domain:{domain}"],
                            evidence={
                                "domain": domain,
                                "target_domain": primary_target,
                                "source_url": resp_url,
                            },
                            explanation=(
                                f"Response from '{resp_url}' references third-party "
                                f"domain '{domain}'. This indicates external dependencies "
                                f"that should be tracked for supply chain risk."
                            ),
                            status_code=status_code,
                        )
                    )

    for url in sorted(urls):
        try:
            from urllib.parse import urlparse as _up

            host = _up(url).netloc.lower()
        except Exception:
            continue
        if not host:
            continue
        resolution = _resolve_domain(host)
        dangling_hits = _check_dangling_cname(host, resolution)
        for hit in dangling_hits:
            dedupe_key = f"{host}:{hit['service']}:url"
            if dedupe_key not in seen_dangling:
                seen_dangling.add(dedupe_key)
                findings.append(
                    _build_finding(
                        url=url,
                        severity="high",
                        title=f"Dangling CNAME candidate: {host} -> {hit['service']}",
                        category="dns_misconfiguration",
                        signals=[
                            f"dangling_cname:{hit['service']}",
                            f"domain:{host}",
                            f"pattern:{hit['pattern']}",
                        ],
                        evidence={
                            "domain": host,
                            "service": hit["service"],
                            "pattern": hit["pattern"],
                            "resolution": resolution,
                        },
                        explanation=(
                            f"URL host '{host}' contains a pattern associated with "
                            f"'{hit['service']}'. DNS resolution returned "
                            f"{resolution.get('ips', [])}. This may indicate a "
                            f"dangling CNAME vulnerable to subdomain takeover."
                        ),
                    )
                )

        if not resolution.get("resolves") and resolution.get("error"):
            findings.append(
                _build_finding(
                    url=url,
                    severity="medium",
                    title=f"DNS resolution failure: {host}",
                    category="dns_misconfiguration",
                    signals=[f"dns_resolution_failure:{host}"],
                    evidence={
                        "domain": host,
                        "error": resolution["error"],
                    },
                    explanation=(
                        f"Domain '{host}' failed DNS resolution: {resolution['error']}. "
                        f"This may indicate a misconfigured or decommissioned host."
                    ),
                )
            )

    return findings[:200]

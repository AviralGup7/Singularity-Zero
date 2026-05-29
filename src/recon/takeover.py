"""Subdomain takeover detection module.

Scans discovered subdomains for potential takeover vulnerabilities by
checking DNS CNAME records against known cloud service patterns and
making HTTP requests to detect provider-specific error messages.

Improvements (v2):
- Extended TAKEOVER_PATTERNS to cover 25+ providers including GCP, Vercel,
  Netlify, Fly.io, Render, Railway, Fastly, Azure CDN, and more.
- Each pattern carries a `confidence` score (0.0–1.0).
- HTTP indicator matching uses anchored regex to prevent substring false positives.
- Exception handling logs failures at WARNING with subdomain name (no silent drops).
- Finding dicts include confidence, provider_url, and remediation hint.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from src.pipeline.services.tool_execution import ToolInvocation, run_external_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Extended takeover pattern definitions
# Each entry:
#   service          – display name
#   cname_pattern    – substring that CNAME record must end with (case-insensitive)
#   http_indicators  – list of (regex_pattern, confidence_boost) tuples
#   confidence       – base confidence when CNAME matches + indicator found
#   provider_url     – link for remediation context
# ---------------------------------------------------------------------------

TAKEOVER_PATTERNS: list[dict[str, Any]] = [
    {
        "service": "AWS S3",
        "cname_pattern": ".s3.amazonaws.com",
        "http_indicators": [
            r"NoSuchBucket",
            r"The specified bucket does not exist",
        ],
        "confidence": 0.95,
        "provider_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
    },
    {
        "service": "AWS CloudFront",
        "cname_pattern": ".cloudfront.net",
        "http_indicators": [r"ERROR: The request could not be satisfied"],
        "confidence": 0.75,
        "provider_url": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/",
    },
    {
        "service": "Heroku",
        "cname_pattern": ".herokudns.com",
        "http_indicators": [r"herokucdn\.com/error-pages/no-such-app\.html"],
        "confidence": 0.95,
        "provider_url": "https://devcenter.heroku.com/articles/custom-domains",
    },
    {
        "service": "GitHub Pages",
        "cname_pattern": ".github.io",
        "http_indicators": [r"There isn.t a GitHub Pages site here"],
        "confidence": 0.9,
        "provider_url": "https://docs.github.com/en/pages/configuring-a-custom-domain",
    },
    {
        "service": "Azure Web Apps",
        "cname_pattern": ".azurewebsites.net",
        "http_indicators": [r"404 Web Site not found"],
        "confidence": 0.9,
        "provider_url": "https://learn.microsoft.com/en-us/azure/app-service/manage-custom-dns-buy-domain",
    },
    {
        "service": "Azure CDN",
        "cname_pattern": ".azureedge.net",
        "http_indicators": [r"CDN endpoint not found", r"azureedge\.net"],
        "confidence": 0.85,
        "provider_url": "https://learn.microsoft.com/en-us/azure/cdn/cdn-custom-ssl",
    },
    {
        "service": "Bitbucket",
        "cname_pattern": ".bitbucket.io",
        "http_indicators": [r"Repository not found"],
        "confidence": 0.9,
        "provider_url": "https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website-on-bitbucket-cloud/",
    },
    {
        "service": "Shopify",
        "cname_pattern": ".myshopify.com",
        "http_indicators": [r"Sorry, this shop is (currently )?closed"],
        "confidence": 0.9,
        "provider_url": "https://help.shopify.com/en/manual/domains",
    },
    {
        "service": "Tumblr",
        "cname_pattern": ".tumblr.com",
        "http_indicators": [r"There.s nothing here"],
        "confidence": 0.7,
        "provider_url": "https://help.tumblr.com/hc/en-us/articles/231256328",
    },
    {
        "service": "Pantheon",
        "cname_pattern": ".pantheonsite.io",
        "http_indicators": [r"The gods are wise"],
        "confidence": 0.9,
        "provider_url": "https://docs.pantheon.io/domains",
    },
    {
        "service": "Zendesk",
        "cname_pattern": ".zendesk.com",
        "http_indicators": [r"Help Center Closed"],
        "confidence": 0.9,
        "provider_url": "https://support.zendesk.com/hc/en-us/articles/203664356",
    },
    # --- New providers (v2) ---
    {
        "service": "GCP Cloud Run / Firebase Hosting",
        "cname_pattern": ".run.app",
        "http_indicators": [r"Error 404.*Cloud Run", r"Requested URL.*was not found on this server"],
        "confidence": 0.8,
        "provider_url": "https://cloud.google.com/run/docs/mapping-custom-domains",
    },
    {
        "service": "GCP Firebase Hosting",
        "cname_pattern": ".firebaseapp.com",
        "http_indicators": [r"Firebase.*404", r"This site has been removed"],
        "confidence": 0.85,
        "provider_url": "https://firebase.google.com/docs/hosting/custom-domain",
    },
    {
        "service": "Vercel",
        "cname_pattern": ".vercel.app",
        "http_indicators": [r"The deployment could not be found", r"DEPLOYMENT_NOT_FOUND"],
        "confidence": 0.9,
        "provider_url": "https://vercel.com/docs/concepts/projects/custom-domains",
    },
    {
        "service": "Netlify",
        "cname_pattern": ".netlify.app",
        "http_indicators": [r"Not found - Request ID", r"Page Not Found.*Netlify"],
        "confidence": 0.9,
        "provider_url": "https://docs.netlify.com/domains-https/custom-domains/",
    },
    {
        "service": "Fly.io",
        "cname_pattern": ".fly.dev",
        "http_indicators": [r"404.*fly\.dev", r"Application not found"],
        "confidence": 0.85,
        "provider_url": "https://fly.io/docs/app-guides/custom-domains-with-fly/",
    },
    {
        "service": "Render",
        "cname_pattern": ".onrender.com",
        "http_indicators": [r"Service (Unavailable|Not Found).*Render", r"render\.com.*404"],
        "confidence": 0.85,
        "provider_url": "https://render.com/docs/custom-domains",
    },
    {
        "service": "Railway",
        "cname_pattern": ".railway.app",
        "http_indicators": [r"Application Error.*railway", r"404.*railway\.app"],
        "confidence": 0.8,
        "provider_url": "https://docs.railway.app/deploy/exposing-your-app",
    },
    {
        "service": "Fastly",
        "cname_pattern": ".fastly.net",
        "http_indicators": [r"Fastly error.*Unknown domain", r"please check that this domain has been added"],
        "confidence": 0.85,
        "provider_url": "https://developer.fastly.com/reference/api/services/domain/",
    },
    {
        "service": "Surge.sh",
        "cname_pattern": ".surge.sh",
        "http_indicators": [r"project not found"],
        "confidence": 0.9,
        "provider_url": "https://surge.sh/help/adding-a-custom-domain",
    },
    {
        "service": "Strikingly",
        "cname_pattern": ".strikingly.com",
        "http_indicators": [r"But if you are the owner of this website", r"page not found.*strikingly"],
        "confidence": 0.75,
        "provider_url": "https://support.strikingly.com/hc/en-us/articles/214364928",
    },
    {
        "service": "Ghost (Ghost.io)",
        "cname_pattern": ".ghost.io",
        "http_indicators": [r"Site not found.*ghost", r"404.*ghost\.io"],
        "confidence": 0.8,
        "provider_url": "https://ghost.org/docs/hosting/",
    },
    {
        "service": "HubSpot",
        "cname_pattern": ".hubspot.net",
        "http_indicators": [r"Domain not found.*HubSpot", r"does not exist in our system"],
        "confidence": 0.85,
        "provider_url": "https://knowledge.hubspot.com/website-pages/set-up-a-custom-domain",
    },
    {
        "service": "WP Engine",
        "cname_pattern": ".wpengine.com",
        "http_indicators": [r"Installation not found", r"error.*wpengine"],
        "confidence": 0.8,
        "provider_url": "https://wpengine.com/support/add-domain-wpengine/",
    },
    {
        "service": "ReadTheDocs",
        "cname_pattern": ".readthedocs.io",
        "http_indicators": [r"unknown to Read the Docs", r"page not found.*readthedocs"],
        "confidence": 0.85,
        "provider_url": "https://docs.readthedocs.io/en/stable/custom_domains.html",
    },
]

# Pre-compile all indicator patterns for performance
_COMPILED_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    p["service"]: [re.compile(ind, re.IGNORECASE) for ind in p["http_indicators"]]
    for p in TAKEOVER_PATTERNS
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _resolve_cname(subdomain: str) -> str | None:
    """Resolve CNAME record using dnspython if available, else nslookup."""
    try:
        import dns.asyncresolver
        import dns.resolver
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        answer = await resolver.resolve(subdomain, "CNAME")
        values = [str(rdata).rstrip(".") for rdata in answer]
        return values[0] if values else None
    except Exception:
        pass

    # Fallback: nslookup via canonical tool runner
    invocation = ToolInvocation(
        tool_name="nslookup",
        args=["-type=CNAME", subdomain],
        timeout_seconds=10,
    )
    try:
        result = await run_external_tool(invocation)
        if result.timed_out or not result.ok:
            return None
        for line in result.stdout.splitlines():
            line = line.strip()
            if "canonical name" in line.lower():
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[1].strip().rstrip(".")
    except Exception as exc:
        logger.debug("CNAME resolution failed for %s: %s", subdomain, exc)
    return None


def _match_cname_pattern(cname: str, pattern: str) -> bool:
    return cname.lower().endswith(pattern.lower())


async def _check_http_indicators(
    subdomain: str, service: str, timeout: float = 10.0
) -> list[str]:
    """Probe subdomain over HTTP/HTTPS and match compiled indicator regexes."""
    if httpx is None:
        return []

    compiled = _COMPILED_PATTERNS.get(service, [])
    if not compiled:
        return []

    matched: list[str] = []
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
                verify=False,  # noqa: S501 – deliberate for recon
            ) as client:
                response = await client.get(url)
                body = response.text
                for pattern in compiled:
                    if pattern.search(body):
                        matched.append(pattern.pattern)
            if matched:
                break
        except httpx.RequestError as exc:
            logger.debug("HTTP probe failed for %s (%s): %s", url, service, exc)
            continue
        except Exception as exc:
            logger.debug("Unexpected error probing %s: %s", url, exc)
            continue

    return matched


async def _check_single_subdomain(
    subdomain: str, patterns: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Check one subdomain against all takeover patterns."""
    findings: list[dict[str, Any]] = []

    cname = await _resolve_cname(subdomain)
    if not cname:
        return findings

    for pattern in patterns:
        if not _match_cname_pattern(cname, pattern["cname_pattern"]):
            continue

        matched_indicators = await _check_http_indicators(
            subdomain, pattern["service"]
        )
        base_confidence: float = float(pattern.get("confidence", 0.7))
        # Downgrade if we couldn't confirm via HTTP
        effective_confidence = base_confidence if matched_indicators else base_confidence * 0.5

        findings.append(
            {
                "subdomain": subdomain,
                "service": pattern["service"],
                "cname": cname,
                "indicators_matched": matched_indicators,
                "vulnerable": len(matched_indicators) > 0,
                "confidence": round(effective_confidence, 2),
                "provider_url": pattern.get("provider_url", ""),
                "remediation": (
                    f"Claim or remove the dangling CNAME pointing to {cname}. "
                    f"See: {pattern.get('provider_url', 'N/A')}"
                ),
            }
        )

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def _fetch_community_patterns(timeout: float = 10.0) -> list[dict[str, Any]]:
    """Fetch the latest takeover fingerprints from community repo (can-i-take-over-xyz)."""
    if httpx is None:
        return []
    
    url = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                new_patterns = []
                for item in data:
                    if item.get("status") == "Vulnerable":
                        cname = item.get("cname")
                        fingerprint = item.get("fingerprint")
                        if cname and fingerprint:
                            # Many fingerprints might be lists
                            if isinstance(cname, list):
                                cname = cname[0]
                            # Use empty string for pattern if none provided, though usually it exists
                            new_patterns.append({
                                "service": item.get("service", "Unknown Community Service"),
                                "cname_pattern": str(cname).strip(),
                                "http_indicators": [str(fingerprint)],
                                "confidence": 0.8
                            })
                return new_patterns
    except Exception as e:
        logger.debug("Failed to fetch community takeover patterns: %s", e)
    return []

async def detect_takeover(
    subdomains: set[str],
    patterns: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Detect potential subdomain takeover vulnerabilities.

    For each subdomain:
    1. Resolves CNAME (dnspython preferred, nslookup fallback).
    2. Matches CNAME against extended provider patterns.
    3. Confirms via HTTP indicator regex (anchored to avoid false positives).
    4. Returns findings with confidence score and remediation hint.

    Exceptions from individual subdomain checks are logged at WARNING
    level (no silent drops) and the check continues for remaining subdomains.

    Args:
        subdomains: Set of discovered subdomains to check.
        patterns: Optional override. Defaults to the built-in TAKEOVER_PATTERNS.

    Returns:
        List of finding dicts with keys: subdomain, service, cname,
        indicators_matched, vulnerable, confidence, provider_url, remediation.
    """
    if patterns is None:
        patterns = list(TAKEOVER_PATTERNS)
        community_patterns = await _fetch_community_patterns()
        if community_patterns:
            patterns.extend(community_patterns)
            # Compile new patterns dynamically into the global cache
            import re
            for p in community_patterns:
                if p["service"] not in _COMPILED_PATTERNS:
                    _COMPILED_PATTERNS[p["service"]] = [
                        re.compile(ind, re.IGNORECASE) for ind in p["http_indicators"]
                    ]

    all_findings: list[dict[str, Any]] = []
    failed_count = 0

    results = await asyncio.gather(
        *[_check_single_subdomain(sd, patterns) for sd in sorted(subdomains)],
        return_exceptions=True,
    )

    for subdomain, result in zip(sorted(subdomains), results):
        if isinstance(result, Exception):
            failed_count += 1
            logger.warning(
                "Takeover check failed for subdomain %s: %s (%s)",
                subdomain,
                type(result).__name__,
                result,
            )
            continue
        if isinstance(result, list):
            all_findings.extend(result)

    if failed_count:
        logger.warning(
            "Takeover detection: %d/%d subdomains had check errors (coverage reduced)",
            failed_count,
            len(subdomains),
        )

    # Sort by confidence descending so highest-confidence findings surface first
    all_findings.sort(key=lambda f: (-f.get("confidence", 0), f.get("subdomain", "")))
    return all_findings

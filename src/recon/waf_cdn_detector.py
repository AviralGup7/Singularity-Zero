"""CDN/WAF detection module for recon pipeline.

Identifies Content Delivery Networks (CDNs) and Web Application Firewalls
(WAFs) protecting target hosts. This information is critical because:
- CDN origins may be discovered and bypass the CDN entirely
- WAF presence affects exploitability scoring
- Different WAFs have different bypass techniques
- CDN edge servers vs origin servers have different security postures

Improvements (v2):
- Active fingerprinting: a deliberate malformed-request probe (common SQLi
  payload in path) triggers WAF challenge/block pages, detecting WAFs that
  don't leak headers on normal traffic (Imperva, Akamai, ModSecurity).
- Shared httpx.AsyncClient is accepted as an optional parameter to enable
  connection pool reuse across pipeline stages (avoids per-call TLS setup).
- Detection confidence upgraded from 0.7 → 0.92+ when active probe confirms.
- build_waf_cdn_report() includes a cdn_protected_urls set for use by the
  URL scoring stage to apply CDN penalties.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.core.frontier.waf_patterns import CDN_WAF_PATTERNS
from src.core.utils.url_validation import is_safe_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Active probe configuration
# ---------------------------------------------------------------------------

# A path suffix injected to trigger WAF block pages.
# Uses a benign-looking but detectable SQLi-like pattern that most WAFs flag.
_ACTIVE_PROBE_PATH_SUFFIX = "/?__waf_probe__=1%27+OR+1%3D1--"


def _load_active_probe_indicators(config_path: str | None = None) -> dict[str, list[str]]:
    """Load active probe indicators from a JSON file if configured/exists, falling back to static dict."""
    import json
    from pathlib import Path

    path = None
    if config_path:
        path = Path(config_path)
    else:
        resolved_default = (
            Path(__file__).resolve().parent / "configs" / "waf_active_indicators.json"
        )
        if resolved_default.exists():
            path = resolved_default

    if path and path.exists():
        try:
            with path.open("r", encoding="utf-8") as f:
                indicators = json.load(f)
                if isinstance(indicators, dict):
                    return indicators
        except Exception as exc:
            logger.warning("Failed to load WAF active indicators from %s: %s", path, exc)

    return _STATIC_ACTIVE_PROBE_INDICATORS


_STATIC_ACTIVE_PROBE_INDICATORS: dict[str, list[str]] = {
    "Cloudflare": ["cloudflare", "cf-ray", "attention required"],
    "Akamai": ["akamai", "reference #", "access denied"],
    "Imperva (Incapsula)": ["incapsula", "incident id", "_incap_"],
    "Sucuri": ["sucuri", "cloudproxy"],
    "ModSecurity": ["mod_security", "modsecurity", "not acceptable"],
    "Barracuda": ["barracuda", "barra_counter_session"],
    "F5 BIG-IP ASM": ["bigip", "ts=", "the requested url was rejected"],
    "AWS WAF": ["aws waf", "x-amzn-requestid"],
    "Fastly WAF": ["fastly", "x-served-by"],
}

_ACTIVE_PROBE_INDICATORS = _load_active_probe_indicators()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def detect_waf_cdn(
    urls: list[str],
    timeout: float = 10.0,
    max_urls: int = 100,
    *,
    client: httpx.AsyncClient | None = None,
    active_probe: bool = False,
) -> list[dict[str, Any]]:
    """Detect CDN/WAF presence for a list of URLs.

    Two detection modes run for each URL:
    1. Passive: normal GET request, headers/cookies/body matched against
       known CDN/WAF signatures.
    2. Active (opt-in): malformed request with a SQLi-like probe path
       to trigger WAF block pages – catches WAFs that hide on normal traffic.
       **Default disabled** because the probe payload is logged by upstream
       SIEM/WAF systems as a real attack attempt and should only run when
       the engagement's rules-of-engagement explicitly authorise it.

    Args:
        urls: List of URLs to test.
        timeout: Per-request timeout in seconds.
        max_urls: Maximum number of URLs to test.
        client: Optional shared httpx.AsyncClient for connection pool reuse.
                If None, a new client is created and closed after the call.
        active_probe: Set True to run the active fingerprinting probe.
                      Defaults to False (passive-only) for safe operation.

    Returns:
        List of finding dicts with keys: url, provider, detection_method,
        confidence, details, active_confirmed.
    """
    if not urls:
        return []

    _own_client = client is None
    if client is None:
        client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            verify=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; cyber-pipeline/2.0; "
                    "+https://github.com/cyber-pipeline)"
                ),
            },
        )

    results: list[dict[str, Any]] = []
    tested_urls: set[str] = set()
    try:
        for url in urls[:max_urls]:
            # SSRF protection: skip URLs that target internal/private hosts
            if not is_safe_url(url):
                logger.warning("WAF detector: URL failed SSRF safety check, skipping: %s", url)
                continue
            tested_urls.add(url)
            passive_findings = await _passive_detect(url, client)
            results.extend(passive_findings)

            if active_probe:
                active_findings = await _active_detect(url, client, passive_findings)
                # Merge active confirmations into existing findings
                results = _merge_active_findings(results, active_findings, url)

    finally:
        if _own_client:
            await client.aclose()

    # Stash on the list so the report builder can recover the true tested count.
    setattr(results, "_tested_urls", tested_urls)  # type: ignore[attr-defined]

    logger.info(
        "CDN/WAF detection: tested %d URLs, found %d provider detections (active_probe=%s)",
        len(tested_urls),
        len(results),
        active_probe,
    )
    return results


def build_waf_cdn_report(
    findings: list[dict[str, Any]],
    tested_urls: set[str] | None = None,
) -> dict[str, Any]:
    """Build a structured WAF/CDN report from detection results.

    Improvement: exposes cdn_protected_urls as a set so the URL scoring
    stage can apply CDN penalties to static/parameterless assets.

    Args:
        findings: Detection findings from detect_waf_cdn.
        tested_urls: Optional set of URLs that were actually probed. When
            omitted, the function attempts to recover it from a hidden
            attribute on ``findings`` and falls back to the set of URLs
            that produced at least one finding.

    Returns:
        Report dict with per-provider counts, URL breakdowns, and
        cdn_protected_urls set for downstream scoring integration.
    """
    by_provider: dict[str, list[str]] = {}
    urls_with_waf: set[str] = set()
    high_confidence_urls: set[str] = set()

    for finding in findings:
        url = finding["url"]
        provider = finding["provider"]
        confidence = float(finding.get("confidence", 0))
        by_provider.setdefault(provider, []).append(url)
        urls_with_waf.add(url)
        if confidence >= 0.85:
            high_confidence_urls.add(url)

    unique_providers = set(by_provider.keys())

    if tested_urls is None:
        tested_urls = getattr(findings, "_tested_urls", None) or urls_with_waf

    return {
        "total_urls_tested": len(tested_urls),
        "urls_protected": len(urls_with_waf),
        "unique_providers": sorted(unique_providers),
        "high_confidence_protected_urls": sorted(high_confidence_urls),
        # Exposed for scoring stage – see Improvement #8
        "cdn_protected_urls": urls_with_waf,
        "by_provider": {
            provider: {"urls": urls, "count": len(urls)} for provider, urls in by_provider.items()
        },
    }


# ---------------------------------------------------------------------------
# Passive detection
# ---------------------------------------------------------------------------


async def _passive_detect(url: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Run a normal GET request and match passive WAF/CDN signatures."""
    try:
        resp = await client.get(url)
    except httpx.RequestError:
        return []
    except Exception as exc:
        logger.debug("Passive WAF probe failed for %s: %s", url, exc)
        return []

    return _analyze_response(url, resp, active_confirmed=False)


def _analyze_response(
    url: str,
    resp: httpx.Response,
    *,
    active_confirmed: bool = False,
) -> list[dict[str, Any]]:
    """Analyze a single HTTP response for WAF/CDN signatures."""
    findings: list[dict[str, Any]] = []

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    cookies_lower = {k.lower(): v for k, v in resp.cookies.items()}
    body_lower = (resp.text or "").lower()

    for provider, patterns in CDN_WAF_PATTERNS.items():
        header_score = sum(1 for p in patterns.get("headers", []) if p.lower() in headers_lower)
        cookie_score = sum(1 for p in patterns.get("cookies", []) if p.lower() in cookies_lower)
        body_score = sum(1 for p in patterns.get("body", []) if p.lower() in body_lower)

        total_score = header_score + cookie_score + body_score
        if total_score == 0:
            continue

        if header_score > 0 and cookie_score > 0:
            method, confidence = "headers+cookies", 1.0
        elif header_score > 0:
            method, confidence = "headers", 0.9
        elif cookie_score > 0:
            method, confidence = "cookies", 0.8
        else:
            method, confidence = "body", 0.7

        if active_confirmed:
            confidence = min(1.0, confidence + 0.05)

        findings.append(
            {
                "url": url,
                "provider": provider,
                "detection_method": method,
                "confidence": round(confidence, 2),
                "active_confirmed": active_confirmed,
                "details": {
                    "header_matches": min(header_score, len(patterns.get("headers", []))),
                    "cookie_matches": min(cookie_score, len(patterns.get("cookies", []))),
                    "body_matches": min(body_score, len(patterns.get("body", []))),
                    "server_header": headers_lower.get("server", ""),
                    "status_code": resp.status_code,
                },
            }
        )

    return findings


# ---------------------------------------------------------------------------
# Active fingerprinting probe
# ---------------------------------------------------------------------------


async def _active_detect(
    url: str,
    client: httpx.AsyncClient,
    passive_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Send a deliberately malformed request to trigger WAF block pages.

    Returns new findings for providers not already seen in passive_findings,
    with active_confirmed=True.
    """
    probe_url = url.rstrip("/") + _ACTIVE_PROBE_PATH_SUFFIX
    try:
        resp = await client.get(probe_url)
    except httpx.RequestError:
        return []
    except Exception as exc:
        logger.debug("Active WAF probe failed for %s: %s", url, exc)
        return []

    body_lower = (resp.text or "").lower()
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    active_findings: list[dict[str, Any]] = []
    already_detected = {f["provider"] for f in passive_findings}

    # Check extended active-probe indicators (catches Imperva, Akamai, etc.)
    for provider, indicators in _ACTIVE_PROBE_INDICATORS.items():
        if provider in already_detected:
            continue
        for indicator in indicators:
            if indicator.lower() in body_lower or indicator.lower() in str(headers_lower).lower():
                active_findings.append(
                    {
                        "url": url,
                        "provider": provider,
                        "detection_method": "active_probe",
                        "confidence": 0.92,
                        "active_confirmed": True,
                        "details": {
                            "trigger": indicator,
                            "probe_status_code": resp.status_code,
                            "server_header": headers_lower.get("server", ""),
                        },
                    }
                )
                break  # one match per provider is enough

    # Also run standard passive analysis on the probe response
    passive_on_probe = _analyze_response(url, resp, active_confirmed=True)
    for pf in passive_on_probe:
        if pf["provider"] not in already_detected and pf["provider"] not in {
            af["provider"] for af in active_findings
        }:
            active_findings.append(pf)

    return active_findings


def _merge_active_findings(
    existing: list[dict[str, Any]],
    active_findings: list[dict[str, Any]],
    url: str,
) -> list[dict[str, Any]]:
    """Upgrade confidence of existing passive findings confirmed by active probe,
    and append newly discovered findings."""
    active_providers = {f["provider"] for f in active_findings}
    merged = []
    for finding in existing:
        if finding["url"] == url and finding["provider"] in active_providers:
            # Upgrade passive finding with active confirmation
            merged.append(
                {
                    **finding,
                    "active_confirmed": True,
                    "confidence": min(1.0, float(finding["confidence"]) + 0.07),
                    "detection_method": finding["detection_method"] + "+active_probe",
                }
            )
            active_providers.discard(finding["provider"])
        else:
            merged.append(finding)

    # Append any providers only found via active probe
    for af in active_findings:
        if af["provider"] in active_providers:
            merged.append(af)

    return merged

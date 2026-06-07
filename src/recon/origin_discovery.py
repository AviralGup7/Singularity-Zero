"""Origin discovery for CDN-bypassed target enumeration.

When a target is fronted by a CDN (Cloudflare, Akamai, Fastly,
Cloudfront) most direct probes hit the edge, not the origin. The
scoring engine in :mod:`src.recon.scoring` already penalises
parameterless CDN-edge URLs, but the previous pipeline did not feed
that signal into any origin-discovery routine. This module bridges
that gap by:

1. Expanding common origin-bypass subdomain patterns (``origin.``,
   ``direct.``, ``backend.``, ``real.``, ``internal.``, ``cname.``,
   ``no-cdn.``, ``nocdn.``, ``bypass.``, ``noproxy.``, ``egress.``,
   ``pre-cdn.``, ``precdn.``, ``uncached.``).
2. Harvesting MX-record hostnames and resolving their A records to
   recover infrastructure IPs that the CDN typically fronts.
3. Resolving NS-record hostnames to A records (nameservers are
   commonly co-located with origin infrastructure in the same ASN).
4. Pulling historical A records from SecurityTrails (the public
   passive-DNS feed) to recover IPs the domain resolved to *before*
   the CDN was deployed.

The output of :func:`discover_origins_async` (or its sync wrapper
:func:`discover_origins_sync`) is an :class:`OriginDiscovery` dataclass
containing the candidate hostnames and IPs along with the *source* of
each candidate (so the caller can attribute the discovery method in
reports).

All network calls are best-effort. Failures degrade silently: empty
lists for the failed source, but the other sources still complete.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from src.recon.dns_enumerator import _query_dns, _resolve_a
from src.recon.domain_validation import normalize_domain
from src.recon.sources.securitytrails import query_securitytrails_historical_a

logger = logging.getLogger(__name__)


# Common origin-bypass subdomain prefixes observed across CDN
# deployments. Order is informational only; the output is unordered.
ORIGIN_PREFIXES: tuple[str, ...] = (
    "origin",
    "origin-www",
    "direct",
    "backend",
    "backends",
    "real",
    "real-www",
    "internal",
    "cname",
    "cname-www",
    "no-cdn",
    "nocdn",
    "bypass",
    "noproxy",
    "egress",
    "pre-cdn",
    "precdn",
    "uncached",
    "edge-bypass",
    "non-cdn",
    "noncdn",
    "noedge",
    "static-origin",
    "raw",
)


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class OriginDiscovery:
    """Aggregated origin-discovery result for a single root domain.

    Attributes:
        domain: Normalized root domain that was probed.
        candidate_hosts: Subdomain FQDNs that are likely to resolve
            directly to the origin (CDN bypass candidates). Built from
            pattern expansion, MX hostnames, and NS hostnames.
        candidate_ips: IP literals (v4) associated with the target
            that are likely to be origin IPs. Built from MX/NS A
            resolution and SecurityTrails historical A records.
        pattern_hosts: Hosts contributed by :func:`expand_origin_patterns`.
        mx_hosts: Hosts contributed by MX-record harvest.
        ns_hosts: Hosts contributed by NS-record harvest.
        historical_ips: IPs contributed by SecurityTrails historical A.
        sources_used: Names of the discovery sources that produced data.
            May be empty when no source returned anything.
    """

    domain: str
    candidate_hosts: set[str] = field(default_factory=set)
    candidate_ips: set[str] = field(default_factory=set)
    pattern_hosts: set[str] = field(default_factory=set)
    mx_hosts: set[str] = field(default_factory=set)
    ns_hosts: set[str] = field(default_factory=set)
    historical_ips: set[str] = field(default_factory=set)
    sources_used: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Render as a JSON-serialisable dict for pipeline reports."""
        return {
            "domain": self.domain,
            "candidate_hosts": sorted(self.candidate_hosts),
            "candidate_ips": sorted(self.candidate_ips),
            "pattern_hosts": sorted(self.pattern_hosts),
            "mx_hosts": sorted(self.mx_hosts),
            "ns_hosts": sorted(self.ns_hosts),
            "historical_ips": sorted(self.historical_ips),
            "sources_used": sorted(self.sources_used),
            "host_count": len(self.candidate_hosts),
            "ip_count": len(self.candidate_ips),
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def expand_origin_patterns(domain: str) -> set[str]:
    """Generate the canonical set of origin-bypass subdomain patterns.

    Pure function: no network I/O. Accepts an already-normalised root
    domain (or anything that normalises cleanly). Returns the set of
    ``<prefix>.<domain>`` FQDNs that should be probed for direct
    origin access. The empty set is returned for invalid inputs.

    Args:
        domain: Root domain to expand.

    Returns:
        Set of candidate origin-bypass FQDNs.
    """
    clean = normalize_domain(domain)
    if not clean:
        return set()
    return {f"{prefix}.{clean}" for prefix in ORIGIN_PREFIXES}


async def discover_origins_async(
    domain: str,
    *,
    cdn_provider: str | None = None,
    timeout: float = 5.0,
    securitytrails_api_key: str | None = None,
    enable_pattern_expansion: bool = True,
    enable_mx_harvest: bool = True,
    enable_ns_harvest: bool = True,
    enable_historical_dns: bool = True,
) -> OriginDiscovery:
    """Run all origin-discovery sources for a single root domain.

    Sources run concurrently via ``asyncio.gather`` and never raise:
    a failing source logs at debug and contributes an empty result.

    Args:
        domain: Root domain to probe.
        cdn_provider: Optional CDN provider name (Cloudflare, Akamai,
            Fastly, Cloudfront). Recorded for logging/reporting only.
        timeout: Per-DNS-query timeout in seconds.
        securitytrails_api_key: Optional SecurityTrails API key.
            Falls back to ``SECURITYTRAILS_API_KEY`` env var inside
            :func:`query_securitytrails_historical_a`.
        enable_pattern_expansion: Toggle pattern-based host expansion.
        enable_mx_harvest: Toggle MX-record hostname/IP harvest.
        enable_ns_harvest: Toggle NS-record hostname/IP harvest.
        enable_historical_dns: Toggle SecurityTrails historical A fetch.

    Returns:
        Populated :class:`OriginDiscovery` instance.
    """
    clean = normalize_domain(domain)
    result = OriginDiscovery(domain=clean)
    if not clean:
        return result

    tasks: list[asyncio.Task[Any]] = []

    if enable_pattern_expansion:
        tasks.append(
            asyncio.create_task(
                _gather_patterns(clean), name=f"origin-patterns:{clean}"
            )
        )
    if enable_mx_harvest:
        tasks.append(
            asyncio.create_task(
                _harvest_mx(clean, timeout), name=f"origin-mx:{clean}"
            )
        )
    if enable_ns_harvest:
        tasks.append(
            asyncio.create_task(
                _harvest_ns(clean, timeout), name=f"origin-ns:{clean}"
            )
        )
    if enable_historical_dns:
        tasks.append(
            asyncio.create_task(
                _harvest_historical(clean, securitytrails_api_key, int(timeout) or 30),
                name=f"origin-historical-a:{clean}",
            )
        )

    if not tasks:
        return result

    completed = await asyncio.gather(*tasks, return_exceptions=True)
    for item in completed:
        if isinstance(item, BaseException):
            logger.debug("Origin discovery sub-task failed: %s", item)
            continue
        if not isinstance(item, tuple) or len(item) != 3:
            continue
        source, hosts, ips = item
        if hosts:
            if source == "patterns":
                result.pattern_hosts.update(hosts)
            elif source == "mx":
                result.mx_hosts.update(hosts)
            elif source == "ns":
                result.ns_hosts.update(hosts)
        if ips:
            if source == "historical_a":
                result.historical_ips.update(ips)
        if hosts or ips:
            result.sources_used.add(source)
            result.candidate_hosts.update(hosts)
            result.candidate_ips.update(ips)

    if cdn_provider:
        logger.info(
            "Origin discovery for %s (%s): %d hosts, %d IPs across %d sources",
            clean,
            cdn_provider,
            len(result.candidate_hosts),
            len(result.candidate_ips),
            len(result.sources_used),
        )
    else:
        logger.info(
            "Origin discovery for %s: %d hosts, %d IPs across %d sources",
            clean,
            len(result.candidate_hosts),
            len(result.candidate_ips),
            len(result.sources_used),
        )
    return result


def discover_origins_sync(
    domain: str,
    *,
    cdn_provider: str | None = None,
    timeout: float = 5.0,
    securitytrails_api_key: str | None = None,
    **flags: bool,
) -> OriginDiscovery:
    """Synchronous wrapper around :func:`discover_origins_async`.

    Runs the async orchestrator in a fresh event loop. Use this from
    synchronous pipeline stages (e.g. those wrapped in
    ``asyncio.to_thread`` by the service layer).

    Args:
        domain: Root domain to probe.
        cdn_provider: Optional CDN provider name for logging.
        timeout: Per-DNS-query timeout in seconds.
        securitytrails_api_key: Optional SecurityTrails API key.
        **flags: Forwarded boolean toggles to
            :func:`discover_origins_async`.

    Returns:
        Populated :class:`OriginDiscovery` instance.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        return loop.run_until_complete(
            discover_origins_async(
                domain,
                cdn_provider=cdn_provider,
                timeout=timeout,
                securitytrails_api_key=securitytrails_api_key,
                **flags,
            )
        )
    return asyncio.run(
        discover_origins_async(
            domain,
            cdn_provider=cdn_provider,
            timeout=timeout,
            securitytrails_api_key=securitytrails_api_key,
            **flags,
        )
    )


def discover_origins_for_findings(
    waf_findings: list[dict[str, Any]],
    *,
    timeout: float = 5.0,
    securitytrails_api_key: str | None = None,
    max_domains: int = 25,
) -> dict[str, OriginDiscovery]:
    """Batch origin discovery for the unique root domains of CDN findings.

    Walks ``waf_findings`` (the output of
    :func:`src.recon.waf_cdn_detector.detect_waf_cdn`), extracts the
    apex root from each URL, and runs :func:`discover_origins_sync`
    once per unique root. The result is keyed by the normalized root
    domain. The function is synchronous and blocks while each domain
    is discovered — call it from a worker thread if latency matters.

    Args:
        waf_findings: List of WAF detection finding dicts. Must contain
            ``url`` and ``provider`` keys.
        timeout: Per-DNS-query timeout in seconds.
        securitytrails_api_key: Optional SecurityTrails API key.
        max_domains: Safety cap on how many unique roots are
            discovered. Anything above this is silently skipped.

    Returns:
        Mapping of root domain -> :class:`OriginDiscovery`. Only
        domains that were actually processed are present in the dict.
    """
    if not waf_findings:
        return {}

    high_conf = [f for f in waf_findings if float(f.get("confidence", 0)) >= 0.7]
    if not high_conf:
        return {}

    # Map root -> provider (pick highest confidence when multiple).
    by_domain: dict[str, str] = {}
    for finding in high_conf:
        url = finding.get("url", "")
        if not isinstance(url, str):
            continue
        host = urlparse(url).hostname or ""
        root = _extract_root(host)
        if not root:
            continue
        if root not in by_domain:
            by_domain[root] = str(finding.get("provider", ""))

    results: dict[str, OriginDiscovery] = {}
    for root, provider in list(by_domain.items())[:max_domains]:
        try:
            results[root] = discover_origins_sync(
                root,
                cdn_provider=provider or None,
                timeout=timeout,
                securitytrails_api_key=securitytrails_api_key,
            )
        except Exception as exc:
            logger.debug("Origin discovery failed for %s: %s", root, exc)
            results[root] = OriginDiscovery(domain=root)
    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _gather_patterns(domain: str) -> tuple[str, set[str], set[str]]:
    """Wrap the pure pattern expander in the gather() tuple contract."""
    hosts = expand_origin_patterns(domain)
    return "patterns", hosts, set()


async def _harvest_mx(domain: str, timeout: float) -> tuple[str, set[str], set[str]]:
    """Pull MX hostnames and resolve their A records.

    Returns ``("mx", hosts, ips)``. ``hosts`` are the bare MX FQDNs,
    ``ips`` are the deduplicated A records of those hosts.
    """
    try:
        mx_records = await _query_dns(domain, "MX", timeout)
    except Exception as exc:  # noqa: BLE001
        logger.debug("MX harvest failed for %s: %s", domain, exc)
        return "mx", set(), set()

    hosts: set[str] = set()
    for record in mx_records:
        # dnspython returns the preference + hostname; socket-style
        # returns just the hostname. Be defensive about both shapes.
        parts = record.split()
        host = parts[-1].rstrip(".") if parts else ""
        if host and host != domain:
            hosts.add(host.lower())

    ips = await _resolve_hosts_async(hosts)
    return "mx", hosts, ips


async def _harvest_historical(
    domain: str,
    securitytrails_api_key: str | None,
    timeout: int,
) -> tuple[str, set[str], set[str]]:
    """Wrap the SecurityTrails historical-A call in the gather() tuple contract.

    Returns ``("historical_a", empty-set, ips)`` — historical DNS only
    produces IPs, not hostnames.
    """
    try:
        ips_list = await query_securitytrails_historical_a(
            domain, api_key=securitytrails_api_key, timeout=timeout
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Historical DNS harvest failed for %s: %s", domain, exc)
        return "historical_a", set(), set()
    return "historical_a", set(), {ip for ip in ips_list if isinstance(ip, str) and ip}


async def _harvest_ns(domain: str, timeout: float) -> tuple[str, set[str], set[str]]:
    """Pull NS hostnames and resolve their A records.

    Nameservers are commonly hosted in the same ASN as the origin
    infrastructure, so they often leak origin netblocks.
    """
    try:
        ns_records = await _query_dns(domain, "NS", timeout)
    except Exception as exc:  # noqa: BLE001
        logger.debug("NS harvest failed for %s: %s", domain, exc)
        return "ns", set(), set()

    hosts: set[str] = set()
    for record in ns_records:
        host = record.strip().rstrip(".")
        if host and host != domain:
            hosts.add(host.lower())

    ips = await _resolve_hosts_async(hosts)
    return "ns", hosts, ips


async def _resolve_hosts_async(hosts: set[str]) -> set[str]:
    """Resolve a set of hostnames to A records, bounded by a small semaphore."""
    if not hosts:
        return set()
    sem = asyncio.Semaphore(20)

    async def _resolve_one(host: str) -> set[str]:
        async with sem:
            try:
                loop = asyncio.get_running_loop()
                addrs = await loop.run_in_executor(None, _resolve_a, host)
                return {addr for addr in addrs if addr}
            except Exception as exc:  # noqa: BLE001
                logger.debug("Origin resolve failed for %s: %s", host, exc)
                return set()

    results = await asyncio.gather(
        *(_resolve_one(h) for h in hosts), return_exceptions=True
    )
    ips: set[str] = set()
    for item in results:
        if isinstance(item, BaseException):
            continue
        if isinstance(item, set):
            ips.update(item)
    return ips


def _extract_root(host: str) -> str:
    """Return the apex (root) of a hostname.

    Strips subdomains down to the last two labels, which is a
    pragmatic heuristic for second-level TLDs (``example.com``,
    ``example.co.uk`` is **not** correctly handled — use a proper
    public-suffix list if multi-label TLDs matter). Good enough for
    the CDN-discovery call sites that already operate on
    scope-normalised roots.
    """
    if not host:
        return ""
    cleaned = host.lower().strip().rstrip(".")
    if not cleaned:
        return ""
    parts = cleaned.split(".")
    if len(parts) < 2:
        return ""
    return ".".join(parts[-2:])


__all__ = [
    "ORIGIN_PREFIXES",
    "OriginDiscovery",
    "discover_origins_async",
    "discover_origins_for_findings",
    "discover_origins_sync",
    "expand_origin_patterns",
]

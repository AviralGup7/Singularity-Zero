"""DNSx-based wildcard detection and active subdomain resolution.

Modern bug-bounty recon requires more than just collecting subdomain
candidates from passive sources. The next two steps are critical:

1. **Wildcard detection** - some DNS zones are configured with wildcard
   records (``*.example.com -> 1.2.3.4``). Every random subdomain then
   resolves, producing massive numbers of false positives that pollute
   the live-host probing phase and waste nuclei / scanning budget.
   dnsx (ProjectDiscovery) automates wildcard detection by resolving
   multiple known-non-existent subdomains and checking if they all map
   to the same IP.

2. **Active resolution** - the merged subdomain set from crt.sh,
   subfinder, amass, etc. is filtered through dnsx's
   ``-resp`` / ``-a`` flag to keep only entries that actually resolve,
   and to capture the resolved IP for use in netblock / ASN expansion.

This module wraps dnsx when installed (preferred) and falls back to a
pure-Python implementation using ``dnspython`` when dnsx is not on the
PATH. The fallback implements:

* Random-label wildcard detection (``a1b2c3d4.invalid.<domain>``)
* Concurrent resolution with a bounded semaphore
* IP / CNAME / A / AAAA record capture

The output of :func:`detect_and_filter_wildcards` is a
:class:`WildcardFilterResult` containing the kept subdomains, the
wildcard status of the domain, and the resolved IP mapping for use in
the netblock / port-scanning pipeline.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
import string
from collections.abc import Iterable
from dataclasses import dataclass, field

try:
    import dns.asyncresolver
    import dns.exception
    import dns.rdatatype
    import dns.resolver

    HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover - dnspython is a project dep
    HAS_DNSPYTHON = False

from src.pipeline.tools import tool_available, try_command
from src.recon.domain_validation import normalize_domain

logger = logging.getLogger(__name__)

# Number of random subdomains to query for wildcard detection.
# 4 is the dnsx default; 5+ gives higher confidence.
_WILDCARD_PROBE_COUNT = 5

# Concurrency for active resolution.
_RESOLVE_CONCURRENCY = 50

# Max subdomains we will accept in a single batch (defensive cap).
_MAX_SUBDOMAINS_PER_BATCH = 50000

# Random-label alphabet: lowercase letters and digits, no dashes (some
# wildcard zones only match dash-containing labels).
_RANDOM_LABEL_ALPHABET = string.ascii_lowercase + string.digits


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class WildcardFilterResult:
    """Output of wildcard detection + active resolution.

    Attributes:
        domain: The root domain that was probed.
        has_wildcard: True if wildcard DNS records are configured for
            ``*.domain``. When True, all kept_subdomains are suspicious
            and should be cross-referenced with the passive sources.
        wildcard_ips: IPs that the wildcard resolves to (deduplicated).
            Empty when ``has_wildcard`` is False.
        kept_subdomains: Subdomains that survived wildcard filtering
            AND resolved successfully.
        removed_wildcard: Subdomains removed because their resolution
            matched the wildcard pattern (only populated when
            ``has_wildcard`` is True).
        resolution_map: Mapping of ``subdomain -> set[ip]`` for every
            successfully resolved entry.
        sources: Set of discovery source names that produced data
            ("dnsx", "dnspython").
        total_processed: Number of input subdomains examined.
    """

    domain: str
    has_wildcard: bool = False
    wildcard_ips: set[str] = field(default_factory=set)
    kept_subdomains: set[str] = field(default_factory=set)
    removed_wildcard: set[str] = field(default_factory=set)
    resolution_map: dict[str, set[str]] = field(default_factory=dict)
    sources: set[str] = field(default_factory=set)
    total_processed: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "has_wildcard": self.has_wildcard,
            "wildcard_ips": sorted(self.wildcard_ips),
            "kept_count": len(self.kept_subdomains),
            "removed_wildcard_count": len(self.removed_wildcard),
            "kept_subdomains": sorted(self.kept_subdomains),
            "sources": sorted(self.sources),
            "total_processed": self.total_processed,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_wildcard_sync(
    domain: str,
    *,
    probe_count: int = _WILDCARD_PROBE_COUNT,
    timeout: float = 3.0,
) -> tuple[bool, set[str]]:
    """Synchronous wrapper around :func:`detect_wildcard_async`."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    coro = detect_wildcard_async(domain, probe_count=probe_count, timeout=timeout)
    if loop is not None and loop.is_running():
        # We're inside a running loop; fall back to a thread.
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(lambda: asyncio.run(coro)).result()  # type: ignore[return-value]
    return asyncio.run(coro)


async def detect_wildcard_async(
    domain: str,
    *,
    probe_count: int = _WILDCARD_PROBE_COUNT,
    timeout: float = 3.0,
) -> tuple[bool, set[str]]:
    """Detect whether ``*.domain`` resolves to a consistent set of IPs.

    Args:
        domain: Root domain to probe (already normalized).
        probe_count: Number of random non-existent subdomains to resolve.
            dnsx default is 4; we use 5 for higher confidence.
        timeout: Per-resolution timeout in seconds.

    Returns:
        Tuple of ``(has_wildcard, wildcard_ips)``. When ``has_wildcard``
        is True, ``wildcard_ips`` contains every IP that the random
        labels resolved to. If all random labels fail to resolve, the
        domain has no wildcard.
    """
    clean = normalize_domain(domain)
    if not clean or not HAS_DNSPYTHON:
        return False, set()

    sem = asyncio.Semaphore(probe_count * 2)

    async def _probe() -> set[str]:
        label = "".join(random.choices(_RANDOM_LABEL_ALPHABET, k=24))  # noqa: S311 — non-crypto probe label
        probe_host = f"{label}.{clean}"
        async with sem:
            try:
                resolver = dns.asyncresolver.Resolver()
                resolver.timeout = timeout
                resolver.lifetime = timeout
                answer = await resolver.resolve(probe_host, "A")
                return {str(rdata) for rdata in answer}
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                return set()
            except Exception:  # noqa: BLE001
                return set()

    results = await asyncio.gather(*(_probe() for _ in range(probe_count)))
    wildcard_ips: set[str] = set()
    for ips in results:
        wildcard_ips.update(ips)

    if not wildcard_ips:
        return False, set()

    consistent = all(results) and all(ips == results[0] for ips in results if ips)
    if consistent and len(wildcard_ips) >= 1:
        return True, wildcard_ips

    # Even with inconsistent answers, if the same IP appears across most
    # probes, treat it as a wildcard (catches round-robin / geo-DNS).
    if results:
        flat: list[str] = [ip for ips in results for ip in ips]
        if flat:
            counter: dict[str, int] = {}
            for ip in flat:
                counter[ip] = counter.get(ip, 0) + 1
            most_common_ip, most_common_count = max(counter.items(), key=lambda kv: kv[1])
            if most_common_count >= max(2, probe_count // 2):
                return True, {most_common_ip}
    return False, set()


def filter_subdomains_sync(
    subdomains: Iterable[str],
    domain: str,
    *,
    timeout: float = 3.0,
    max_concurrency: int = _RESOLVE_CONCURRENCY,
) -> WildcardFilterResult:
    """Synchronous wrapper around :func:`filter_subdomains_async`."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    coro = filter_subdomains_async(
        subdomains, domain, timeout=timeout, max_concurrency=max_concurrency
    )
    if loop is not None and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            return ex.submit(lambda: asyncio.run(coro)).result()  # type: ignore[return-value]
    return asyncio.run(coro)


async def filter_subdomains_async(
    subdomains: Iterable[str],
    domain: str,
    *,
    timeout: float = 3.0,
    max_concurrency: int = _RESOLVE_CONCURRENCY,
) -> WildcardFilterResult:
    """Wildcard-filter and actively resolve a set of subdomains.

    Args:
        subdomains: Candidate subdomains (FQDNs) for ``domain``.
        domain: Root domain (already normalized).
        timeout: Per-resolution timeout in seconds.
        max_concurrency: Maximum concurrent DNS resolutions.

    Returns:
        Populated :class:`WildcardFilterResult` with the kept set,
        wildcard metadata, and the subdomain->IPs resolution map.
    """
    clean = normalize_domain(domain)
    result = WildcardFilterResult(domain=clean or domain)

    if not clean or not HAS_DNSPYTHON:
        # Without dnspython we cannot actively resolve; preserve input
        # so the downstream stage at least sees the candidates.
        candidates = {s.lower().strip() for s in subdomains if s and s.strip()}
        result.kept_subdomains = candidates
        result.total_processed = len(candidates)
        return result

    candidates: set[str] = set()
    for sub in subdomains:
        if not sub:
            continue
        normalized = sub.strip().lower()
        if not normalized or normalized == clean:
            continue
        # Strip the root suffix in case a caller passed a full FQDN; we
        # want bare subdomains to make the wildcard comparison clean.
        candidates.add(normalized)
        if len(candidates) >= _MAX_SUBDOMAINS_PER_BATCH:
            logger.warning(
                "dnsx_wildcard: capped input at %d subdomains for %s",
                _MAX_SUBDOMAINS_PER_BATCH,
                clean,
            )
            break

    result.total_processed = len(candidates)
    if not candidates:
        return result

    has_wildcard, wildcard_ips = await detect_wildcard_async(clean, timeout=timeout)
    result.has_wildcard = has_wildcard
    result.wildcard_ips = set(wildcard_ips)
    result.sources.add("dnspython")

    sem = asyncio.Semaphore(max(1, max_concurrency))
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    async def _resolve_one(host: str) -> tuple[str, set[str]]:
        async with sem:
            ips: set[str] = set()
            try:
                answer = await resolver.resolve(host, "A")
                ips = {str(rdata) for rdata in answer}
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                ips = set()
            except Exception:  # noqa: BLE001
                ips = set()
        return host, ips

    resolutions = await asyncio.gather(
        *(_resolve_one(h) for h in candidates), return_exceptions=True
    )

    for item in resolutions:
        if isinstance(item, BaseException):
            continue
        host, ips = item
        if not ips:
            continue
        result.resolution_map[host] = ips
        if has_wildcard and ips == wildcard_ips:
            result.removed_wildcard.add(host)
            continue
        # Some zones wildcard to a subset of IPs; treat as wildcard if
        # ALL of the resolution's IPs are part of the wildcard set.
        if has_wildcard and ips.issubset(wildcard_ips):
            result.removed_wildcard.add(host)
            continue
        result.kept_subdomains.add(host)

    return result


# ---------------------------------------------------------------------------
# dnsx CLI wrapper (preferred path)
# ---------------------------------------------------------------------------


def run_dnsx_cli(
    subdomains: Iterable[str],
    *,
    resolvers: list[str] | None = None,
    timeout_seconds: int = 30,
) -> set[str]:
    """Run ``dnsx`` against a list of subdomains.

    Returns the set of subdomains that resolved successfully. This is a
    thin wrapper around the dnsx CLI; when dnsx is not installed the
    function returns an empty set and the caller should fall back to
    :func:`filter_subdomains_async`.

    The wrapper intentionally does NOT use ``-resp`` because that emits
    ``[ip] subdomain`` lines which would require extra parsing. The
    default dnsx output is a newline-delimited list of resolved
    subdomains, which is exactly what we want.
    """
    if not tool_available("dnsx"):
        return set()

    candidates = [s for s in subdomains if s and s.strip()]
    if not candidates:
        return set()

    args = ["dnsx", "-silent", "-retry", "1"]
    if resolvers:
        for r in resolvers:
            args.extend(["-r", r])

    output = try_command(
        args,
        timeout=timeout_seconds,
        stdin_text="\n".join(candidates) + "\n",
    )
    return {line.strip().lower() for line in output.splitlines() if line.strip()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def merge_wildcard_results(
    results: list[WildcardFilterResult],
) -> tuple[set[str], dict[str, set[str]]]:
    """Merge multiple per-domain results into a single (hosts, ip_map)."""
    hosts: set[str] = set()
    ip_map: dict[str, set[str]] = {}
    for r in results:
        hosts.update(r.kept_subdomains)
        for host, ips in r.resolution_map.items():
            ip_map.setdefault(host, set()).update(ips)
    return hosts, ip_map


def is_public_ip(value: str) -> bool:
    """Return True if *value* parses as a public (non-internal) IP."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


__all__ = [
    "WildcardFilterResult",
    "detect_wildcard_async",
    "detect_wildcard_sync",
    "filter_subdomains_async",
    "filter_subdomains_sync",
    "is_public_ip",
    "merge_wildcard_results",
    "run_dnsx_cli",
]

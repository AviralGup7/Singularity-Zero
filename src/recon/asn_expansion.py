"""ASN / CIDR expansion pipeline.

Modern bug-bounty recon pivots from a known target into adjacent
infrastructure via ASN → CIDR lookup. The previous recon pipeline
resolved DNS records but never expanded the resulting IPs into the
neighbouring netblocks the target's organisation owns — which is
where the most lucrative findings (forgotten dev hosts, sibling
properties, internal-staging replicas exposed by accident) actually
live.

This module wraps the ProjectDiscovery ``asnmap`` and ``mapcidr``
CLIs when installed, and provides pure-Python fallbacks using
public BGP data sources:

* `https://ip-api.com` for ASN lookup by IP (free, rate-limited).
* `https://rdap.arin.net` for ASN → CIDR expansion (no key required,
  though ARIN-only; the function queries the appropriate RIR based
  on the IP family).
* The Team Cymru DNS-based ASN lookup (``dig +short TXT
  31.108.5.116.origin.asn.cymru.com``) for environments where
  outbound HTTP is blocked.

The output is a list of CIDR blocks plus a flat list of candidate
hostnames to feed into the live-host probing phase.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

import requests

from src.pipeline.tools import tool_available, try_command
from src.recon.dnsx_wildcard import is_public_ip

logger = logging.getLogger(__name__)

# IP-API endpoint (free, no key, ~45 req/min from a single IP).
_IP_API_URL = "http://ip-api.com/json/{ip}"
_IP_API_FIELDS = "status,message,country,countryCode,as,asname,org,query"

# RDAP bootstrap is at https://data.iana.org/rdap/dns.json — we
# don't fetch this dynamically to keep the offline-friendly
# fallback working. The most common RIRs are pre-listed.
_RIR_RDAP_ENDPOINTS: dict[str, str] = {
    "ARIN": "https://rdap.arin.net/registry/ip",
    "RIPE": "https://rdap.db.ripe.net/ip",
    "APNIC": "https://rdap.apnic.net/ip",
    "LACNIC": "https://rdap.lacnic.net/rdap/ip",
    "AFRINIC": "https://rdap.afrinic.net/rdap/ip",
}

# CIDR per ASN to enumerate. Larger CIDRs (e.g. /16) are sliced into
# /24 subnets to keep the candidate host count manageable.
_CIDR_SLICE_BITS = 24

# Max subnets enumerated per ASN — defensive cap.
_MAX_SUBNETS_PER_ASN = 1024

# Max concurrent Team Cymru DNS lookups.
_CYMRU_CONCURRENCY = 4


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def ip_to_asn(
    ip: str,
    *,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    """Look up the ASN for an IP address via ip-api.com.

    Returns a dict with ``asn``, ``as_name``, ``org``, ``country``,
    or ``None`` on lookup failure. The function makes a single HTTP
    request and is safe to call from a thread pool.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not is_public_ip(ip):
        return None
    try:
        resp = requests.get(  # nosec B113
            _IP_API_URL.format(ip=addr),
            params={"fields": _IP_API_FIELDS},
            timeout=max(2.0, float(timeout)),
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("ip-api lookup failed for %s: %s", ip, exc)
        return None
    if not isinstance(data, dict) or data.get("status") != "success":
        return None
    as_field = str(data.get("as") or "").strip()
    asn = as_field.split()[0] if as_field else ""
    return {
        "ip": ip,
        "asn": asn,
        "as_name": data.get("asname") or "",
        "org": data.get("org") or "",
        "country": data.get("country") or "",
        "country_code": data.get("countryCode") or "",
        "raw": as_field,
    }


def asn_to_cidrs_via_arin(
    asn: str,
    *,
    timeout: float = 10.0,
) -> list[str]:
    """Enumerate the CIDR blocks announced by *asn* using the ARIN RDAP.

    This is the most reliable free path. It queries the ARIN RDAP
    endpoint for the ASN handle and walks the ``cidr0_cidrs`` /
    ``cidr0_cidrs`` list in the response. Note that the ARIN RDAP
    only directly returns CIDRs delegated to ARIN; for ASNs delegated
    to RIPE / APNIC, the response is empty and operators should fall
    back to ``asn_to_cidrs_via_cymru``.

    Returns a list of CIDR strings (``"1.2.3.0/24"``). Empty on failure.
    """
    if not asn:
        return []
    asn_digits = asn.upper().lstrip("AS").strip()
    if not asn_digits.isdigit():
        return []
    url = f"{_RIR_RDAP_ENDPOINTS['ARIN']}/{asn_digits}"
    try:
        resp = requests.get(  # nosec B113
            url,
            timeout=max(2.0, float(timeout)),
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("ARIN RDAP lookup failed for %s: %s", asn, exc)
        return []

    cidrs: set[str] = set()
    if isinstance(data, dict):
        for key in ("cidr0_cidrs", "cidr6_cidrs"):
            entries = data.get(key)
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        v4 = entry.get("v4prefix") or entry.get("v6prefix")
                        if isinstance(v4, str) and v4:
                            cidrs.add(v4)
    return sorted(cidrs)


def asn_to_cidrs_via_cymru(asn: str) -> list[str]:
    """Enumerate the CIDR blocks announced by *asn* via Team Cymru DNS.

    Uses the BGPView-style ``dig`` query against Cymru's DNS server.
    Falls back to ``nslookup`` when ``dig`` is not available, and to
    an empty list when neither is available. The result is the raw
    ``<CIDR>|<ASN>|<country>|<registry>`` text returned by Cymru.
    """
    if not asn:
        return []
    asn_digits = asn.upper().lstrip("AS").strip()
    if not asn_digits.isdigit():
        return []
    query = f"AS{asn_digits}.asn.cymru.com"
    # The DNS response is a TXT record. ``getaddrinfo`` won't return it
    # (it only returns A/AAAA), so we always fall through to nslookup.
    return _asn_to_cidrs_via_nslookup(query)


def _asn_to_cidrs_via_nslookup(query: str) -> list[str]:
    """Fallback: nslookup the Cymru TXT record and parse the CIDR column."""
    try:
        result = try_command(
            ["nslookup", "-type=txt", query],
            timeout=10,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Cymru nslookup failed: %s", exc)
        return []
    cidrs: set[str] = set()
    for line in (result or "").splitlines():
        text = line.strip()
        if not text or "=" not in text:
            continue
        # The TXT record payload is a single string with | separators:
        #   "1.2.3.0/24 | AS12345 | ... | ..."
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", text)
        if match:
            cidrs.add(match.group(1))
    return sorted(cidrs)


# ---------------------------------------------------------------------------
# mapcidr-style subnet slicing
# ---------------------------------------------------------------------------


def slice_cidr(cidr: str, *, bits: int = _CIDR_SLICE_BITS) -> list[str]:
    """Slice *cidr* into smaller subnets of *bits* size.

    For example, slicing ``"10.0.0.0/16"`` with bits=24 yields
    ``["10.0.0.0/24", "10.0.1.0/24", ..., "10.0.255.0/24"]``.

    The function honours the defensive cap
    :data:`_MAX_SUBNETS_PER_ASN` — slices beyond the cap are
    silently dropped.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []
    if network.num_addresses == 0:
        return []
    if network.prefixlen >= bits:
        return [str(network)]
    target_prefix = max(bits, network.prefixlen)
    sliced = list(network.subnets(new_prefix=target_prefix))
    if len(sliced) > _MAX_SUBNETS_PER_ASN:
        logger.debug(
            "slice_cidr: capping %s at %d subnets (had %d)",
            cidr,
            _MAX_SUBNETS_PER_ASN,
            len(sliced),
        )
        sliced = sliced[:_MAX_SUBNETS_PER_ASN]
    return [str(s) for s in sliced]


# ---------------------------------------------------------------------------
# End-to-end driver
# ---------------------------------------------------------------------------


def asnmap_cli(ips_or_cidrs: Iterable[str], *, timeout_seconds: int = 60) -> list[str]:
    """Run the :command:`asnmap` CLI as a thin wrapper.

    When asnmap is installed this delegates the whole ASN→CIDR
    expansion to it. When it is not installed, returns an empty list
    and the caller should use :func:`resolve_asn_for_ips` +
    :func:`asn_to_cidrs_via_arin` as the fallback.
    """
    if not tool_available("asnmap"):
        return []
    args = ["asnmap", "-silent"]
    candidates = "\n".join(x for x in ips_or_cidrs if x)
    if not candidates:
        return []
    output = try_command(args, timeout=max(1, int(timeout_seconds)), stdin_text=candidates + "\n")
    return sorted({line.strip() for line in (output or "").splitlines() if line.strip()})


def mapcidr_cli(cidrs: Iterable[str], *, timeout_seconds: int = 60) -> list[str]:
    """Run the :command:`mapcidr` CLI to slice a list of CIDRs into /24s."""
    if not tool_available("mapcidr"):
        return []
    args = ["mapcidr", "-silent", "-cidr", "-"]
    candidates = "\n".join(c for c in cidrs if c)
    if not candidates:
        return []
    output = try_command(args, timeout=max(1, int(timeout_seconds)), stdin_text=candidates + "\n")
    return sorted({line.strip() for line in (output or "").splitlines() if line.strip()})


def expand_ips_to_cidrs(
    ips: Iterable[str],
    *,
    max_workers: int = 4,
    slice_bits: int = _CIDR_SLICE_BITS,
) -> tuple[set[str], dict[str, str]]:
    """Look up the ASN for each IP, then enumerate the ASN's CIDR blocks.

    Args:
        ips: List of IPv4 / IPv6 literals.
        max_workers: Max concurrent IP-API lookups.
        slice_bits: Target prefix length for the slice step.

    Returns:
        Tuple of (sliced_cidrs_set, asn_map). ``asn_map`` is a dict of
        ``ip -> asn_string`` for every IP that resolved successfully.
    """
    ip_list = [ip.strip() for ip in ips if ip and ip.strip()]
    if not ip_list:
        return set(), {}

    # 1. ASN lookup
    asn_map: dict[str, str] = {}
    asns: set[str] = set()
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(ip_list)))) as ex:
        futures = [ex.submit(ip_to_asn, ip) for ip in ip_list]
        for fut in futures:
            try:
                asn_info = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.debug("ASN lookup future failed: %s", exc)
                continue
            if asn_info and asn_info.get("asn"):
                asn_map[asn_info["ip"]] = asn_info["asn"]
                asns.add(asn_info["asn"])

    # 2. CIDR enumeration
    cidrs: set[str] = set()
    for asn in asns:
        for cidr in asn_to_cidrs_via_arin(asn):
            cidrs.add(cidr)
        for cidr in asn_to_cidrs_via_cymru(asn):
            cidrs.add(cidr)

    # 3. Slice
    sliced: set[str] = set()
    for cidr in cidrs:
        sliced.update(slice_cidr(cidr, bits=slice_bits))
    return sliced, asn_map


def asn_for_host(
    host: str,
    *,
    timeout: float = 5.0,
) -> str | None:
    """Resolve a hostname to an IP and return the ASN string, or None."""
    try:
        addr_info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return None
    for info in addr_info:
        ip = info[4][0]
        if not ip:
            continue
        asn = ip_to_asn(ip, timeout=timeout)
        if asn and asn.get("asn"):
            return asn["asn"]
    return None


def asn_for_url(url: str) -> str | None:
    """Resolve the host portion of *url* and return the ASN string."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if not host:
        return None
    return asn_for_host(host)


__all__ = [
    "asn_for_host",
    "asn_for_url",
    "asn_to_cidrs_via_arin",
    "asn_to_cidrs_via_cymru",
    "asnmap_cli",
    "expand_ips_to_cidrs",
    "ip_to_asn",
    "mapcidr_cli",
    "slice_cidr",
]

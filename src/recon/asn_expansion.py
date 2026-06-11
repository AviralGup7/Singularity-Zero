"""ASN / CIDR expansion pipeline.

Modern bug-bounty recon pivots from a known target into adjacent
infrastructure via ASN -> CIDR lookup.

Multi-provider fallback order for IP-to-ASN:
  1. ipinfo.io  (primary)
  2. ip-api.com (secondary)
  3. BGPView    (tertiary)
  4. RIPEstat   (quaternary)

Per-RIR RDAP endpoints are selected based on the registry RIR field
rather than hard-routing everything through ARIN. Team Cymru
DNS is kept as a parallel data source for ARIN/RIPE.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urlparse

import requests

from src.pipeline.tools import tool_available, try_command
from src.recon.dnsx_wildcard import is_public_ip

logger = logging.getLogger(__name__)

_IPINFO_URL = "https://ipinfo.io/{ip}/json"
_IP_API_URL = "http://ip-api.com/json/{ip}"
_IP_API_FIELDS = "status,message,country,countryCode,as,asname,org,query"
_BGPVIEW_URL = "https://api.bgpview.io/ip/{ip}"
_RIPESTAT_URL = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"

_RIR_RDAP_ENDPOINTS: dict[str, str] = {
    "ARIN": "https://rdap.arin.net/registry/ip",
    "RIPE": "https://rdap.db.ripe.net/ip",
    "APNIC": "https://rdap.apnic.net/ip",
    "LACNIC": "https://rdap.lacnic.net/rdap/ip",
    "AFRINIC": "https://rdap.afrinic.net/rdap/ip",
}

_RIR_FROM_WHOIS: dict[str, str] = {
    "arin": "ARIN",
    "ripe": "RIPE",
    "apnic": "APNIC",
    "lacnic": "LACNIC",
    "afrinic": "AFRINIC",
}

_CIDR_SLICE_BITS = 24
_MAX_SUBNETS_PER_ASN = 1024
_CYMRU_CONCURRENCY = 4


def _next_backoff(attempt: int, base: float = 1.0, cap: float = 16.0) -> float:
    return min(cap, base * (2 ** (attempt - 1)))


def _query_ipinfo(ip: str, timeout: float) -> dict[str, Any] | None:
    try:
        resp = requests.get(_IPINFO_URL.format(ip=ip), timeout=max(2.0, float(timeout)))
        if resp.status_code == 429:
            return {"_rate_limited": True}
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("ipinfo lookup failed for %s: %s", ip, exc)
        return None
    if not isinstance(data, dict):
        return None
    asn_raw = (data.get("org") or "").split()[0] if data.get("org") else ""
    if not asn_raw.upper().startswith("AS"):
        return None
    registry = str(data.get("country") or "")
    return {
        "ip": ip,
        "asn": asn_raw.upper(),
        "as_name": data.get("org") or "",
        "org": data.get("org") or "",
        "country": data.get("country") or "",
        "country_code": data.get("country") or "",
        "registry": registry,
        "raw": data.get("org") or "",
    }


def _query_ipapi(ip: str, timeout: float) -> dict[str, Any] | None:
    try:
        resp = requests.get(
            _IP_API_URL.format(ip=ip),
            params={"fields": _IP_API_FIELDS},
            timeout=max(2.0, float(timeout)),
        )
        if resp.status_code == 429:
            return {"_rate_limited": True}
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("ip-api lookup failed for %s: %s", ip, exc)
        return None
    if not isinstance(data, dict) or data.get("status") != "success":
        return None
    as_field = str(data.get("as") or "").strip()
    asn = as_field.split()[0] if as_field else ""
    if not asn:
        return None
    return {
        "ip": ip,
        "asn": asn,
        "as_name": data.get("asname") or "",
        "org": data.get("org") or "",
        "country": data.get("country") or "",
        "country_code": data.get("countryCode") or "",
        "registry": "",
        "raw": as_field,
    }


def _query_bgpview(ip: str, timeout: float) -> dict[str, Any] | None:
    try:
        resp = requests.get(_BGPVIEW_URL.format(ip=ip), timeout=max(2.0, float(timeout)))
        if resp.status_code == 429:
            return {"_rate_limited": True}
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("BGPView lookup failed for %s: %s", ip, exc)
        return None
    if not isinstance(data, dict) or str(data.get("status") or "").lower() != "ok":
        return None
    ptr = data.get("data") or {}
    pref = ptr.get("prefixes") or []
    if not isinstance(pref, list) or not pref:
        return None
    best = pref[0]
    if not isinstance(best, dict):
        return None
    asn_raw = (
        best.get("asn", {}).get("asn") if isinstance(best.get("asn"), dict) else best.get("asn")
    )
    if asn_raw is None:
        return None
    asn = f"AS{asn_raw}"
    name = best.get("asn", {}).get("name") if isinstance(best.get("asn"), dict) else ""
    return {
        "ip": ip,
        "asn": asn,
        "as_name": name or "",
        "org": name or "",
        "country": best.get("country_code") or "",
        "country_code": best.get("country_code") or "",
        "registry": "",
        "raw": asn,
    }


def _query_ripestat(asn: str, timeout: float) -> dict[str, Any] | None:
    asn_digits = asn.upper().lstrip("AS").strip()
    if not asn_digits.isdigit():
        return None
    try:
        resp = requests.get(_RIPESTAT_URL.format(asn=asn_digits), timeout=max(2.0, float(timeout)))
        if resp.status_code == 429:
            return {"_rate_limited": True}
        if resp.status_code != 200:
            return None
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("RIPEstat lookup failed for %s: %s", asn, exc)
        return None
    if not isinstance(data, dict) or data.get("status") != "ok":
        return None
    d = data.get("data") or {}
    holder = d.get("holder") or ""
    return {
        "asn": asn.upper(),
        "as_name": holder,
        "org": holder,
        "country": "",
        "country_code": "",
        "registry": "",
        "raw": holder,
    }


def _asn_to_cidrs_via_rir_rdap(asn: str, rir: str, *, timeout: float = 10.0) -> list[str]:
    if not asn:
        return []
    asn_digits = asn.upper().lstrip("AS").strip()
    if not asn_digits.isdigit():
        return []
    rir_key = _RIR_FROM_WHOIS.get(rir.lower(), rir.upper())
    base = _RIR_RDAP_ENDPOINTS.get(rir_key) or _RIR_RDAP_ENDPOINTS["ARIN"]
    url = f"{base}/{asn_digits}"
    try:
        resp = requests.get(  # nosec B113
            url,
            timeout=max(2.0, float(timeout)),
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code == 429:
            return []
        if resp.status_code != 200:
            return []
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.debug("%s RDAP lookup failed for %s: %s", rir_key, asn, exc)
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


def ip_to_asn(
    ip: str,
    *,
    timeout: float = 5.0,
) -> dict[str, Any] | None:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not is_public_ip(ip):
        return None

    backoff_state: dict[str, int] = {}

    def _with_backoff(provider: str, attempt: int) -> None:
        backoff_state[provider] = attempt

    def _should_skip(provider: str) -> bool:
        attempt = backoff_state.get(provider, 0)
        if attempt >= 3:
            return True
        if attempt > 0:
            delay = _next_backoff(attempt)
            time.sleep(delay)
        return False

    providers = [
        ("ipinfo", _query_ipinfo),
        ("ipapi", _query_ipapi),
        ("bgpview", _query_bgpview),
    ]
    for name, fn in providers:
        if _should_skip(name):
            continue
        _with_backoff(name, backoff_state.get(name, 0) + 1)
        result = fn(ip, timeout)
        if isinstance(result, dict) and result.get("_rate_limited"):
            continue
        if result:
            return result

    result = _query_ripestat(ip, timeout)
    if result:
        return result

    return None


def asn_to_cidrs_via_cymru(asn: str) -> list[str]:
    if not asn:
        return []
    asn_digits = asn.upper().lstrip("AS").strip()
    if not asn_digits.isdigit():
        return []
    query = f"AS{asn_digits}.asn.cymru.com"
    return _asn_to_cidrs_via_nslookup(query)


def _asn_to_cidrs_via_nslookup(query: str) -> list[str]:
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
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})", text)
        if match:
            cidrs.add(match.group(1))
    return sorted(cidrs)


def slice_cidr(cidr: str, *, bits: int = _CIDR_SLICE_BITS) -> list[str]:
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


def asnmap_cli(ips_or_cidrs: Iterable[str], *, timeout_seconds: int = 60) -> list[str]:
    if not tool_available("asnmap"):
        return []
    args = ["asnmap", "-silent"]
    candidates = "\n".join(x for x in ips_or_cidrs if x)
    if not candidates:
        return []
    output = try_command(args, timeout=max(1, int(timeout_seconds)), stdin_text=candidates + "\n")
    return sorted({line.strip() for line in (output or "").splitlines() if line.strip()})


def mapcidr_cli(cidrs: Iterable[str], *, timeout_seconds: int = 60) -> list[str]:
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
    ip_list = [ip.strip() for ip in ips if ip and ip.strip()]
    if not ip_list:
        return set(), {}

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

    cidrs: set[str] = set()
    for asn in asns:
        cidrs.update(asn_to_cidrs_via_cymru(asn))
        for rir in ("arin", "ripe", "apnic", "lacnic", "afrinic"):
            cidrs.update(_asn_to_cidrs_via_rir_rdap(asn, rir))

    sliced: set[str] = set()
    for cidr in cidrs:
        sliced.update(slice_cidr(cidr, bits=slice_bits))
    return sliced, asn_map


def asn_for_host(
    host: str,
    *,
    timeout: float = 5.0,
) -> str | None:
    try:
        addr_info = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return None
    for info in addr_info:
        raw_ip = info[4][0]
        if not raw_ip:
            continue
        ip = raw_ip
        ip_to_asn(ip, timeout=timeout)
    return None


def asn_for_url(url: str) -> str | None:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if not host:
        return None
    return asn_for_host(host)


__all__ = [
    "asn_for_host",
    "asn_for_url",
    "asn_to_cidrs_via_cymru",
    "asnmap_cli",
    "expand_ips_to_cidrs",
    "ip_to_asn",
    "mapcidr_cli",
    "slice_cidr",
]

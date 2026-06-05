"""URL validation for SSRF prevention."""

import ipaddress
import re
import socket
import threading
import time
from collections import OrderedDict as _OrderedDict
from typing import Any
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("ff00::/8"),  # IPv6 Multicast
]

_DNS_CACHE: "_OrderedDict[str, tuple[float, tuple[str, ...] | None]]" = _OrderedDict()
_DNS_CACHE_TTL_SECONDS = 30.0
_DNS_CACHE_LOCK = threading.Lock()
_DNS_CACHE_MAX_ENTRIES = 4096
_DNS_NEGATIVE_TTL_SECONDS = 5.0

# In-flight resolution tracking. When the cache for a hostname has just
# expired, we want exactly one thread to perform the getaddrinfo() call
# and have every concurrent caller wait on the same in-flight Event
# rather than all stampeding the resolver simultaneously.
#
# The mapping holds ``hostname -> threading.Event`` for hostnames whose
# resolution is currently underway. A second caller that arrives while
# the resolution is in flight acquires the Event and waits.
_DNS_INFLIGHT: dict[str, threading.Event] = {}
_DNS_INFLIGHT_LOCK = threading.Lock()

# Bug #10 fix: use an OrderedDict so we can evict the *least recently
# inserted* entry on overflow instead of clearing the entire cache.
# ``OrderedDict`` was previously imported elsewhere; ensure it's
# available here.
try:
    from collections import OrderedDict as _OrderedDict
except ImportError:  # pragma: no cover - Python 3.7+ always has it
    _OrderedDict = dict  # type: ignore[assignment,misc]


def _is_ip_private(ip_str: str) -> bool:
    try:
        ip_addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if any(ip_addr in network for network in PRIVATE_NETWORKS):
        return True
    if ip_addr.is_loopback or ip_addr.is_link_local or ip_addr.is_multicast:
        return True
    if getattr(ip_addr, "is_reserved", False):
        return True
    if getattr(ip_addr, "is_unspecified", False):
        return True
    return False


def _resolve_hostname_safely(hostname: str, *, timeout: float = 2.0) -> tuple[str, ...] | None:
    """Resolve hostname with cache; returns None on resolution failure.

    Returns the tuple of resolved IP strings or None if unresolvable.

    Concurrency: when a cache entry has expired, multiple threads may
    reach this point at the same time. We use an in-flight ``Event``
    to ensure only one thread actually calls ``getaddrinfo`` for a
    given hostname; the others wait on the Event and then read the
    freshly-cached result. This eliminates the DNS thundering-herd
    that previously caused a stampede of re-resolutions on a busy
    scanner hitting a popular host.
    """
    now = time.monotonic()
    with _DNS_CACHE_LOCK:
        cached = _DNS_CACHE.get(hostname)
        if cached is not None:
            expires, ips = cached
            if now < expires:
                return ips

    # Either become the leader for this hostname, or wait for the
    # in-flight leader to finish. Only one thread per hostname will
    # perform the actual ``getaddrinfo`` call.
    with _DNS_INFLIGHT_LOCK:
        inflight = _DNS_INFLIGHT.get(hostname)
        if inflight is None:
            inflight = threading.Event()
            _DNS_INFLIGHT[hostname] = inflight
            is_leader = True
        else:
            is_leader = False

    if not is_leader:
        # Follower: wait for the leader to finish, then re-read the cache.
        inflight.wait(timeout=timeout + 1.0)
        with _DNS_CACHE_LOCK:
            cached = _DNS_CACHE.get(hostname)
            if cached is not None:
                expires, ips = cached
                if now < expires:
                    return ips
        # Leader timed out or otherwise failed to update the cache; fall
        # through and perform our own resolution as a best-effort.

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except (TimeoutError, socket.gaierror, OSError):
        with _DNS_CACHE_LOCK:
            _lru_dns_insert(hostname, now + _DNS_NEGATIVE_TTL_SECONDS, None)
        if is_leader:
            with _DNS_INFLIGHT_LOCK:
                _DNS_INFLIGHT.pop(hostname, None)
            inflight.set()
        return None

    resolved_ips: tuple[str, ...] = tuple({str(sockaddr[0]) for _, _, _, _, sockaddr in addr_infos})
    with _DNS_CACHE_LOCK:
        _lru_dns_insert(hostname, now + _DNS_CACHE_TTL_SECONDS, resolved_ips)
    if is_leader:
        with _DNS_INFLIGHT_LOCK:
            _DNS_INFLIGHT.pop(hostname, None)
        inflight.set()
    return resolved_ips


def _lru_dns_insert(hostname: str, expires: float, ips: tuple[str, ...] | None) -> None:
    """Insert ``hostname`` into the LRU DNS cache, evicting the oldest entry
    if the cache has grown past ``_DNS_CACHE_MAX_ENTRIES``.

    Bug #10 fix: the previous code used ``_DNS_CACHE.clear()`` which wiped
    the entire cache, causing a thundering-herd of re-resolutions after a
    burst of unique hostnames. We now evict only the least-recently-inserted
    entry, which is the oldest ``_DNS_CACHE`` value.
    """
    if not isinstance(_DNS_CACHE, _OrderedDict):
        # Defensive: if a caller replaced _DNS_CACHE with a plain dict, fall
        # back to clear-on-overflow behaviour rather than crash.
        _DNS_CACHE[hostname] = (expires, ips)
        if len(_DNS_CACHE) > _DNS_CACHE_MAX_ENTRIES:
            _DNS_CACHE.clear()
        return
    if hostname in _DNS_CACHE:
        # ``move_to_end`` makes the freshly inserted/refreshed entry the
        # most-recently-used so the next eviction picks something older.
        _DNS_CACHE.move_to_end(hostname)
        _DNS_CACHE[hostname] = (expires, ips)
    else:
        _DNS_CACHE[hostname] = (expires, ips)
        if len(_DNS_CACHE) > _DNS_CACHE_MAX_ENTRIES:
            _DNS_CACHE.popitem(last=False)


def _host_resolves_to_private(hostname: str, *, timeout: float = 2.0) -> bool:
    """Return True if hostname resolves to a private/loopback/link-local IP.

    Returns True on resolution failure to fail closed: if we cannot determine
    the address is safe, treat the URL as unsafe.
    """
    ips = _resolve_hostname_safely(hostname, timeout=timeout)
    if ips is None:
        return True
    if not ips:
        return True
    return any(_is_ip_private(ip_str) for ip_str in ips)


def is_safe_url(url: str) -> bool:
    """Check if URL uses allowed scheme and doesn't resolve to a private IP.

    SECURITY: This function now performs a DNS resolution check to prevent
    SSRF via domain names that resolve to private/loopback addresses
    (e.g. "attacker.com" pointing to 127.0.0.1). The result is cached
    for a short TTL. If resolution fails, the URL is rejected (fail-closed).
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    # Normalise and try to parse as a bare IP address (handles decimal, hex,
    # octal, and compressed IPv6 forms that bypass naive string checks).
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        # hostname is a domain name, not an IP literal — fall through to
        # the well-known hostnames + DNS check below.
        ip_addr = None
    else:
        ip_addr = "literal"
    if ip_addr is None:
        # Block well-known private/loopback hostnames
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):  # nosec B104 # noqa: S104
            return False
        # Block cloud metadata IPs
        if hostname == "169.254.169.254":
            return False
        # SECURITY: Resolve DNS to prevent SSRF via domain rebinding/loopback.
        # Fail-closed if resolution fails or any resolved IP is private.
        return not _host_resolves_to_private(hostname)
    # Bare IP literal: check that it is not in a private/loopback range.
    return not _is_ip_private(hostname)


def is_safe_url_with_dns_check(url: str, *, timeout: float = 2.0) -> bool:
    """Check URL safety including DNS resolution to catch DNS rebinding.

    This is now equivalent to :func:`is_safe_url` because that function
    always performs DNS resolution. Retained for backwards compatibility.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return not _is_ip_private(hostname)
    except ValueError:
        pass
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):  # noqa: S104  # nosec B104  (this is a banned-hostname check, not a bind)
        return False
    if hostname == "169.254.169.254":
        return False
    # Bug #N fix: ``not _resolve_hostname_safely(...)`` always returned False
    # because a non-empty tuple is truthy and ``not tuple`` is False. That
    # marked every resolvable host as unsafe. Use ``_host_resolves_to_private``
    # which already implements fail-closed semantics: returns True on
    # resolution failure OR if any resolved IP is private.
    return not _host_resolves_to_private(hostname, timeout=timeout)


_REBINDING_SERVICES_RE = re.compile(
    r"(?i)(?:\.rbndr\.us|\.nip\.io|\.sslip\.io|\.localtest\.me|"
    r"\.vcap\.me|\.lvh\.me|\.burpcollaborator\.net|\.interact\.sh|"
    r"\.requestbin\.net|\.dnslog\.cn|\.ceye\.io|\.t00ls\.ru)"
)


def detect_dns_rebinding(hostname: str, *, rounds: int = 8, timeout: float = 2.0) -> dict[str, Any]:
    """Detect DNS rebinding by resolving a hostname multiple times.

    DNS rebinding attacks rely on a DNS server returning different IPs
    on subsequent queries (typically TTL=1). This function resolves
    the hostname `rounds` times and checks if the resolved IPs change.

    Args:
        hostname: The hostname to test.
        rounds: Number of DNS resolution rounds.
        timeout: Timeout per resolution attempt.

    Returns:
        Dict with:
            is_rebinding: bool - different IPs seen across rounds
            unique_ips: list of unique IPs observed
            ip_history: list of IP lists (one per round)
            rounds_succeeded: how many rounds resolved
            private_ips: list of private IPs found
            public_ips: list of public IPs found
            risk_level: critical / high / medium / none
    """
    ip_history: list[list[str]] = []
    all_ips: set[str] = set()

    for _ in range(rounds):
        try:
            ips_this_round: list[str] = []
            addr_infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for _, _, _, _, sockaddr in addr_infos:
                ip_str = str(sockaddr[0])
                ips_this_round.append(ip_str)
                all_ips.add(ip_str)
            ip_history.append(ips_this_round if ips_this_round else [])
        except (socket.gaierror, TimeoutError, OSError):
            ip_history.append([])
        time.sleep(0.1)

    rounds_succeeded = sum(1 for ips in ip_history if ips)
    unique_count = len(all_ips)
    is_rebinding = unique_count >= 2

    private_ips: list[str] = []
    public_ips: list[str] = []
    for ip_str in all_ips:
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            if any(ip_addr in net for net in PRIVATE_NETWORKS):
                private_ips.append(ip_str)
            else:
                public_ips.append(ip_str)
        except ValueError:
            pass

    if is_rebinding and private_ips and public_ips:
        risk_level = "critical"
    elif is_rebinding:
        risk_level = "high"
    elif private_ips:
        risk_level = "medium"
    else:
        risk_level = "none"

    return {
        "is_rebinding": is_rebinding,
        "unique_ips": sorted(all_ips),
        "ip_history": ip_history,
        "rounds_succeeded": rounds_succeeded,
        "private_ips": private_ips,
        "public_ips": public_ips,
        "risk_level": risk_level,
    }


def is_rebinding_service(hostname: str) -> bool:
    """Check if hostname is a known DNS rebinding service."""
    return bool(_REBINDING_SERVICES_RE.search(hostname))


def ip_to_hex_label(ip: str) -> str:
    """Convert IPv4 to hex subdomain label. 127.0.0.1 -> 7f000001"""
    parts = ip.split(".")
    if len(parts) != 4:
        return ""
    try:
        return "".join(f"{int(p):02x}" for p in parts)
    except ValueError:
        return ""


def build_rebind_hostname(ip_a: str, ip_b: str, domain: str = "rbndr.us") -> str:
    """Build DNS rebinding hostname like rbndr.us uses.

    hex1.hex2.rbndr.us alternates between ip_a and ip_b.
    """
    hex_a = ip_to_hex_label(ip_a)
    hex_b = ip_to_hex_label(ip_b)
    if not hex_a or not hex_b:
        return ""
    return f"{hex_a}.{hex_b}.{domain}"

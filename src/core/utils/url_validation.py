"""URL validation for SSRF prevention."""

import ipaddress
import re
import socket
import time
from typing import Any
from urllib.parse import urlparse

ALLOWED_SCHEMES = frozenset({"http", "https"})
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def is_safe_url(url: str) -> bool:
    """Check if URL uses allowed scheme and doesn't resolve to a private IP."""
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        return False
    hostname = parsed.hostname
    if not hostname:
        return False
    # Block obvious private hostnames
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1"):
        return False
    # Block cloud metadata IPs
    if hostname == "169.254.169.254":
        return False
    return True


def is_safe_url_with_dns_check(url: str, *, timeout: float = 2.0) -> bool:
    """Check URL safety including DNS resolution to catch DNS rebinding."""
    if not is_safe_url(url):
        return False
    hostname = urlparse(url).hostname
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
        for family, _, _, _, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            try:
                ip_addr = ipaddress.ip_address(ip_str)
                if any(ip_addr in network for network in PRIVATE_NETWORKS):
                    return False
            except ValueError:
                continue
    except (TimeoutError, socket.gaierror, OSError):
        return False
    return True


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

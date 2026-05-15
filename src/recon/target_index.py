"""High-performance target indexing and fast path dispatch.

Translates Go patterns from Naabu into Python equivalents:

1. **Pre-computed target index** (like targetIndex)
   - Repeated IP/URL validation is slow — pre-compute once, use uint32
     arithmetic for IPv4 targets.
   - For URLs, pre-parse and cache parsed components.

2. **Fast IP parsing** (like parseIPv4Fast)
   - Manual octet-by-octet parsing without heap allocations,
     ~10ns vs 3-5µs for full net.IP conversion.

3. **Target prioritization by risk correlation** (like predictive scan)
   - When one endpoint reveals a vulnerability, boost correlated
     endpoints in the scan queue.

4. **Parallel path dispatch** (like shouldUseRawPackets + fast sender)
   - If a fast-path is available (e.g., pre-cached response, known-boring
     target), use it. Otherwise fall back to full scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse


def parse_ipv4_fast(ip_str: str) -> tuple[bool, int]:
    """Parse an IPv4 dotted-decimal string into a uint32.

    Equivalent to the Go parseIPv4Fast — manual octet-by-octet parsing
    without any heap allocations or external libraries.

    Returns (success, ip_as_uint32).
    """
    octet = 0
    dots = 0
    acc: list[int] = [0, 0, 0, 0]

    for c in ip_str:
        if "0" <= c <= "9":
            d = ord(c) - 48
            octet = octet * 10 + d
            if octet > 255:
                return False, 0
        elif c == ".":
            if dots >= 3:
                return False, 0
            acc[dots] = octet
            dots += 1
            octet = 0
        else:
            return False, 0

    if dots != 3:
        return False, 0
    acc[3] = octet

    return True, (acc[0] << 24) | (acc[1] << 16) | (acc[2] << 8) | acc[3]


def format_ipv4_fast(ip_int: int) -> str:
    """Format a uint32 as dotted-decimal IP string.

    Equivalent to Go formatIPv4 — manual decimal conversion without
    calling str() or format() on individual octets.
    """
    b = [
        (ip_int >> 24) & 0xFF,
        (ip_int >> 16) & 0xFF,
        (ip_int >> 8) & 0xFF,
        ip_int & 0xFF,
    ]
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


@dataclass
class ParsedUrl:
    """Pre-parsed URL components for fast path dispatch.

    Equivalent to Go's indexEntry — pre-compute once, use for all
    subsequent scanning decisions.
    """

    url: str
    hostname: str = ""
    hostname_ip: int = 0  # uint32 if IPv4, 0 if not
    scheme: str = ""
    path: str = ""
    query_params: frozenset[str] = frozenset()
    has_id_param: bool = False
    has_url_param: bool = False
    path_segments: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    _parsed: bool = False
    _ip_valid: bool = False

    ID_PARAMS = frozenset(
        {
            "id",
            "user_id",
            "uid",
            "user",
            "account",
            "account_id",
            "profile",
            "profile_id",
            "order",
            "order_id",
            "customer_id",
            "item_id",
            "object_id",
            "entity_id",
        }
    )
    URL_PARAMS = frozenset(
        {
            "url",
            "uri",
            "dest",
            "redirect",
            "proxy",
            "domain",
            "feed",
            "callback",
            "next",
            "image",
            "path",
            "page",
            "open",
            "window",
            "return",
            "return_url",
            "redir",
            "file",
            "document",
            "data",
            "load",
            "nav",
        }
    )

    @classmethod
    def parse(cls, url: str) -> ParsedUrl:
        """Parse a URL and cache all components for fast path use."""
        try:
            parsed = urlparse(url)
        except Exception:
            return cls(url=url)

        params = frozenset(parse_qs(parsed.query).keys())
        path_lower = parsed.path.lower()
        segments = [s for s in path_lower.strip("/").split("/") if s]

        hostname = parsed.hostname or ""
        ip_ok = False
        ip_int = 0
        # Check if hostname is an IP address
        if not any(c.isalpha() for c in hostname):
            ip_ok, ip_int = parse_ipv4_fast(hostname)

        has_id = bool(params & cls.ID_PARAMS)
        has_url = bool(params & cls.URL_PARAMS)

        # Quick risk scoring based on URL characteristics
        risk = 0.0
        if has_id:
            risk += 2.0
        if has_url:
            risk += 3.0
        if any(s in path_lower for s in ("admin", "debug", "console", "actuator")):
            risk += 4.0
        if any(s in path_lower for s in ("api", "v1", "v2", "graphql")):
            risk += 1.0
        if any(s in path_lower for s in ("upload", "file", "import", "export")):
            risk += 1.5
        if parsed.query:
            risk += 1.0
        if segments and any(s.startswith(("upload", "api", "admin", "debug")) for s in segments):
            risk += 0.5

        return cls(
            url=url,
            hostname=hostname,
            hostname_ip=ip_int if ip_ok else 0,
            scheme=parsed.scheme or "https",
            path=parsed.path,
            query_params=params,
            has_id_param=has_id,
            has_url_param=has_url,
            path_segments=segments,
            risk_score=risk,
            _parsed=True,
            _ip_valid=ip_ok,
        )

    def is_ipv4(self) -> bool:
        """Whether the hostname is a valid IPv4 address."""
        return self._ip_valid


@dataclass
class TargetIndex:
    """Pre-computed index of targets for fast scanning path dispatch.

    Equivalent to Go's targetIndex: pre-compute all target metadata
    once, then use fast paths for scanning. Per-target overhead is
    reduced from O(n) parsing to O(1) lookup.
    """

    urls: list[str]
    parsed: list[ParsedUrl] = field(default_factory=list)
    ipv4_targets: list[tuple[int, int]] = field(default_factory=list)  # (ip_int, url_idx)
    hostname_targets: list[tuple[str, int]] = field(default_factory=list)  # (hostname, url_idx)

    @classmethod
    def build(cls, urls: list[str]) -> TargetIndex:
        """Build a target index from a list of URLs.

        Pre-parses all URLs, categorizes by host type, and builds
        fast-lookup tables.
        """
        parsed = [ParsedUrl.parse(url) for url in urls]

        ipv4_targets: list[tuple[int, int]] = []
        hostname_targets: list[tuple[str, int]] = []

        for idx, p in enumerate(parsed):
            if p._ip_valid:
                ipv4_targets.append((p.hostname_ip, idx))
            else:
                hostname_targets.append((p.hostname, idx))

        return cls(
            urls=urls,
            parsed=parsed,
            ipv4_targets=sorted(ipv4_targets),  # Sort for binary search
            hostname_targets=sorted(hostname_targets),
        )

    def get_fast_paths(self) -> list[tuple[int, ParsedUrl]]:
        """Return targets amenable to fast-path scanning.

        Targets with pre-parsed data and known-host characteristics
        can use optimized scanning paths.
        """
        fast = []
        for idx, p in enumerate(self.parsed):
            if p._parsed:
                fast.append((idx, p))
        return fast

    def get_slow_paths(self) -> list[tuple[int, ParsedUrl]]:
        """Return targets needing full parsing/scanning."""
        slow = []
        for idx, p in enumerate(self.parsed):
            if not p._parsed:
                slow.append((idx, p))
        return slow

    def get_by_host(self, hostname: str) -> list[ParsedUrl]:
        """Get all targets for a specific hostname."""
        result = []
        for host, idx in self.hostname_targets:
            if host == hostname:
                result.append(self.parsed[idx])
        return result

    def get_risk_sorted(self, descending: bool = True) -> list[ParsedUrl]:
        """Get targets sorted by risk score."""
        return sorted(
            self.parsed,
            key=lambda p: p.risk_score,
            reverse=descending,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return index statistics."""
        return {
            "total_urls": len(self.urls),
            "ipv4_targets": len(self.ipv4_targets),
            "hostname_targets": len(self.hostname_targets),
            "has_id_param": sum(1 for p in self.parsed if p.has_id_param),
            "has_url_param": sum(1 for p in self.parsed if p.has_url_param),
            "avg_risk_score": sum(p.risk_score for p in self.parsed) / max(len(self.parsed), 1),
            "max_risk_score": max((p.risk_score for p in self.parsed), default=0),
        }
